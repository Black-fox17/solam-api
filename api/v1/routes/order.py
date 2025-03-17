from fastapi import APIRouter,Depends, status, HTTPException
from fastapi.encoders import jsonable_encoder
from api.v1.services.user import user_service
from api.v1.schemas.order import OrderSchema
from sqlalchemy.orm import Session
from api.db.database import get_db
from api.v1.services.order import order_service
from api.utils.success_response import success_response

orders = APIRouter(prefix="/order", tags=["Orders"])

@orders.post("/create", status_code=status.HTTP_201_CREATED)
async def create(
    order: OrderSchema,
    db: Session = Depends(get_db)
):
    order.service = order.service.upper()
    order_log = order_service.create_order(order,db)
    return success_response(
        status_code=201,
        message="order created successfully",
        data=jsonable_encoder(order_log)
    )

@orders.get("")
async def get_orders(current_user = Depends(user_service.get_current_user), db: Session = Depends(get_db)):

    orders = order_service.fetch_all(db = db)
    if not orders:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No orders found for the specified action"
            )
    return success_response(
        status_code=200,
        message="Orders retrieved successfully",
        data=jsonable_encoder(orders)
    )