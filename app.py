from flask import Flask, request, jsonify
from jwcrypto import jwk, jwt
import json
import jwt as jpy
import requests

app = Flask(__name__)


def get_priv_key_string():
    with open("priv.json", "r") as priv:
        return priv.read()


@app.route("/auth", methods=["GET"])
def auth_view():
    auth_token = request.headers.get("Authorization")
    if auth_token:
        token_header = jpy.get_unverified_header(auth_token)
        if "jku" in token_header:
            r = requests.get(token_header.get("jku")).json()
            j = json.dumps(r)
            keyset = jwk.JWKSet.from_json(j)
            print("Keyset", keyset)
            mykey = keyset.get_key(kid="we45")
            print("Key", mykey)
            decoded_token = jwt.JWT(key=mykey, jwt=auth_token)
            print("Decoded", decoded_token)
            json_decode = json.loads(decoded_token.claims)
            print(json_decode)
            if json_decode.get("user"):
                return jsonify(
                    {
                        "success": True,
                        "error": False,
                        "message": "Congrats, you are a {}".format(
                            json_decode.get("user")
                        ),
                    }
                )
            else:
                return (
                    jsonify(
                        {"success": False, "error": True, "message": "Unauthorized"}
                    ),
                    403,
                )


@app.route("/init", methods=["GET"])
def init():
    key = jwk.JWK.generate(kty="RSA", size=2048)
    json_key = key.export(private_key=True)
    pub_key = json.loads(key.export_public())
    print(pub_key)
    with open("priv.json", "w") as priv:
        priv.write(json_key)
    pub_key["use"] = "sig"
    pub_key["kid"] = "we45"
    pub_key["alg"] = "RS256"
    final_pub = json.dumps({"keys": [pub_key]})
    with open("legit.json", "w") as legit:
        legit.write(final_pub)

    return jsonify(
        {
            "success": True,
            "error": False,
            "message": "Keypair successfully generated",
            "data": {"pub": "legit.json", "priv": "priv.json"},
        }
    )


@app.route("/login", methods=["POST"])
def login():
    try:
        if "username" in request.get_json() and "password" in request.get_json():
            if request.get_json().get("username") == "admin" and request.get_json().get(
                "password"
            ):
                jku_url = "http://localhost:8000/legit.json"
                priv = jwk.JWK.from_json(get_priv_key_string())
                token = jwt.JWT(
                    header={"alg": "RS256", "jku": jku_url}, claims={"user": "user"}
                )
                token.make_signed_token(priv)
                final = token.serialize()
                return jsonify(
                    {
                        "success": True,
                        "error": False,
                        "message": "Successfully Authenticated",
                        "token": final,
                    }
                )
            else:
                return jsonify(
                    {"success": False, "error": True, "message": "Invalid credentials"}
                )

    except Exception as e:
        return jsonify({"error": True, "success": False, "message": e.__str__})


if __name__ == "__main__":
    app.run(debug=True)
