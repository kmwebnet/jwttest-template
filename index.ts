import express from "express";
import request from "request-promise";
import jwt from "jsonwebtoken";

const app: express.Express = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//CORS config
app.use(
  (req: express.Request, res: express.Response, next: express.NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "*");
    res.header("Access-Control-Allow-Headers", "*");
    next();
  }
);

const port = process.env.PORT || 443;

app.listen(port, () => {
  console.log("Start on port" + port);
});

const CONSTS = {
  SERVICE_ACCOUNT: "",
  CLIENT_ID: "",
  CLIENT_SECRET: "",
  PRIVATEKEY:
    "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKlOdSDkZMdNI9\n9Ggi8fxUOygNaW5SIt+thCdb\n-----END PRIVATE KEY-----\n",
};

app.get("/", function (req, res) {
  res.json({ status: "OK" });
});

app.post("/auth", async function (req, res) {
  var username = req.body.username;
  var password = req.body.password;

  //auth
  if (username === "" && password === "") {
    const token = await getServerToken();
    res.json({
      token: token,
    });
  } else {
    res.json({
      error: "auth error",
    });
  }
});

async function getServerToken() {
  const iss = CONSTS.CLIENT_ID;
  const sub = CONSTS.SERVICE_ACCOUNT;
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60 * 60;
  const cert = CONSTS.PRIVATEKEY;
  const options = {
    method: "POST",
    url: ``,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    },
    form: {
      grant_type: encodeURIComponent(
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ),
      assertion: jwt.sign({ iss: iss, sub: sub, iat: iat, exp: exp }, cert, {
        algorithm: "RS256",
      }),
      client_id: encodeURIComponent(CONSTS.CLIENT_ID),
      client_secret: encodeURIComponent(CONSTS.CLIENT_SECRET),
      scope: "user,user.read",
    },
  };
  return new Promise((resolve, reject) => {
    request(options)
      .then((res) => {
        const result = JSON.parse(res);
        if (result.message) throw "Could not get token";
        resolve(result);
      })
      .catch((error) => {
        console.log(`Auth Error: ${error}`);
        reject(error);
      });
  });
}
