from flask_restx import Namespace, Resource

health_ns = Namespace("health", description="Health check operations")


@health_ns.route("")
class HealthResource(Resource):
    def get(self):
        return {"success": True, "status": "ok", "message": "API is healthy"}, 200
