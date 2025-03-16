from api.v1.schemas.order import OrderSchema
from api.v1.models.order import ContactRequest
from sqlalchemy.orm import Session

class Orders:
    def create_order(self, schema: OrderSchema, db: Session):
        ""
        order = ContactRequest(**schema.model_dump())

        db.add(order)
        db.commit()
        db.refresh(order)

        return order
    


order_service = Orders()