from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]


def userExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if userExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid username"
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 6
        })
        retJson = {
            "status": 200,
            "msg": "Successfully signed up to the API"
        }

        return jsonify(retJson)


def verify_pw(username, password):
    if not userExist(username):
        return False
    else:
        hased_pw = users.find({
            "Username": username
        })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf-8'), hased_pw) == hased_pw:
        return True
    else:
        return False


def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


class Detect(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not userExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid username"
            }
            return jsonify(retJson)

        correct_pw = verify_pw(username, password)

        if not correct_pw:
            retJson = {
                "status": 302,
                "msg": "Invalid Password"
            }
            return jsonify(retJson)

        number_tokens = countTokens(username)
        if number_tokens <= 0:
            retJson = {
                "status": 303,
                "msg": "Out of tokens"
            }
            return jsonify(retJson)

        nlp = spacy.load("en_core_web_sm-2.2.5")

        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)
        retJson = {
            "status": 200,
            "similarity": ratio,
            "msg": "Success to calculate the similarity"
        }
        return jsonify(retJson)

        current_tokens = countTokens(username)

        users.update({
            "Username": " username",
        }, {
            "$set": {
                "Tokens": current_tokens - 1
            }
        })

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill = postedData["refill"]
        if not userExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid username"
            }
            return jsonify(retJson)

        correct_pw = "abc123"
        if not password == correct_pw:
            retJson = {
                "status": 304,
                "msg": "Invalid admin pass"
            }
            return jsonify(retJson)

        current_tokens = countTokens(username)
        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": refill
            }
        })

        retJson = {
            "status": "200",
            "msg": "Success to refill"
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
