import base64
import json
import pickle
import unittest

from dockerized_labs.insec_des_lab.main import app, serialize_user


class InsecureDeserializationTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_normal_user_can_be_deserialized(self):
        response = self.client.post(
            "/serialize", data={"username": "guest"}
        )
        self.assertEqual(response.status_code, 200)

        token = response.data.decode().split("Your serialized token: ")[1].split("<")[0]
        response = self.client.post("/deserialize", data={"serialized_data": token})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome guest", response.data)

    def test_admin_flag_cannot_be_changed(self):
        token = serialize_user(type("U", (), {"username": "attacker", "is_admin": False})())

        body = json.loads(base64.b64decode(token).decode())
        body["data"] = json.dumps({"username": "attacker", "is_admin": True})
        forged = base64.b64encode(json.dumps(body).encode()).decode()

        response = self.client.post("/deserialize", data={"serialized_data": forged})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid token signature", response.data)

    def test_pickle_payload_is_rejected(self):
        class Payload:
            def __reduce__(self):
                return (eval, ("__import__('os').popen('id').read()",))

        payload = base64.b64encode(pickle.dumps(Payload())).decode()

        response = self.client.post("/deserialize", data={"serialized_data": payload})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"uid=", response.data)


if __name__ == "__main__":
    unittest.main()
