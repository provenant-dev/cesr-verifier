import json

import falcon
from keri.core import coring, parsing
from keri.vdr import verifying, eventing


def setup(app, hby, vdb, reger, local=False):
    """ Set up verifying endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Database environment for the verifier
        reger (Reger): Database environment for credential registries

    """

    tvy = eventing.Tevery(reger=reger, db=hby.db, local=local)
    vry = verifying.Verifier(hby=hby, reger=reger)

    loadEnds(app, hby, vdb, tvy, vry)


def loadEnds(app, hby, vdb, tvy, vry):
    """ Load and map endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Verifier database environment
        tvy (Tevery): transaction event log event processor
        vry (Verifier): credential verification processor

    """

    healthEnd = HealthEndpoint()
    app.add_route("/health", healthEnd)
    credEnd = PresentationResourceEndpoint(hby, vdb, tvy, vry)
    app.add_route("/presentations/{said}", credEnd)

    return []


class PresentationResourceEndpoint:
    """ Credential presentation resource endpoint class

    This class allows for a PUT to a credential SAID specific endpoint to trigger credential presentation
    verification.

    """

    def __init__(self, hby, vdb, tvy, vry):
        """ Create credential presentation resource endpoint instance

        Parameters:
            hby (Habery): Database environment for exposed KERI AIDs
            vdb (VerifierBaser): Verifier database environment
            tvy (Tevery): transaction event log event processor
            vry (Verifier): credential verification event processor

        """
        self.hby = hby
        self.vdb = vdb
        self.tvy = tvy
        self.vry = vry

    def on_put(self, req, rep, said):
        """  Credential Presentation Resource PUT Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            said: qb64 SAID of credential being presented

        ---
         summary: Present vLEI ECR credential for AID authorization to other endpoints
         description: Present vLEI ECR credential for AID authorization to other endpoints
         tags:
            - Credentials
         parameters:
           - in: path
             name: said
             schema:
                type: string
             description: qb64 SAID of credential being presented
         requestBody:
             required: true
             content:
                application/json+cesr:
                  schema:
                    type: application/json
                    format: text
         responses:
           202:
              description: Credential Presentation accepted

        """
        rep.content_type = "application/json"

        if req.content_type not in ("application/json+cesr",):
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg=f"invalid content type={req.content_type} for VC presentation")).encode(
                "utf-8")
            return

        ims = req.bounded_stream.read()

        self.vry.cues.clear()

        parsing.Parser().parse(ims=ims,
                               kvy=self.hby.kvy,
                               tvy=self.tvy,
                               vry=self.vry)

        found = False
        while self.vry.cues:
            msg = self.vry.cues.popleft()
            if "creder" in msg:
                creder = msg["creder"]
                if creder.said == said:
                    found = True
                    break

        if not found:
            rep.status = falcon.HTTP_BAD_REQUEST
            rep.data = json.dumps(dict(msg=f"credential {said} from body of request did not verify")).encode("utf-8")
            return

        print(f"Credential {said} presented.")

        saider = coring.Saider(qb64=said)
        now = coring.Dater()

        self.vdb.iss.pin(keys=(saider.qb64,), val=now)

        rep.status = falcon.HTTP_ACCEPTED
        rep.data = json.dumps(
            dict(msg=f"{said} is a valid credential ")).encode(
            "utf-8")
        return


class HealthEndpoint:
    def __init__(self):
        pass

    def on_get(self, req, rep):
        rep.content_type = "application/json"
        rep.status = falcon.HTTP_OK
        rep.data = json.dumps(dict(msg="vLEI verification service is healthy")).encode("utf-8")
        return
