# Regression test: app.api.cloud must import on Python 3.12 and FastAPI must
# inject the real Request object into the EC2 action route.
import unittest


class CloudRouterImportTest(unittest.TestCase):
    def test_cloud_router_imports_and_injects_request(self):
        from app.api import cloud  # raised NameError before the fix

        routes = [
            r for r in cloud.router.routes
            if getattr(r, "path", "").endswith("/ec2/{account_id}/instances/{instance_id}/action")
        ]
        self.assertEqual(len(routes), 1)
        dependant = routes[0].dependant
        self.assertEqual(dependant.request_param_name, "request")
        self.assertNotIn("request", [p.name for p in dependant.query_params])
        self.assertNotIn("request", [p.name for p in dependant.body_params])


if __name__ == "__main__":
    unittest.main()
