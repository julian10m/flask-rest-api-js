import uuid
from flask import Flask, request
from flask_smorest import abort
from db import stores, items

app = Flask(__name__)

@app.get("/stores")
def get_stores():
    return { "stores" : list(stores.values()) }

@app.get("/stores/<int:store_id>")
def get_store(store_id):    
    try:
        return stores[store_id]
    except KeyError:
        abort(404, message="Store not found")

@app.post("/stores")
def create_store():
    data = request.get_json()

    if "name" not in data:
        abort(400, message="Bad request. Include name.")

    for store in stores.values():
        if store["name"] == data["name"]:
            abort(400, message="Store already exists.")

    store_id = uuid.uuid4().hex
    new_store = {
        **data,
        "id": store_id,
    }
    stores[store_id] = new_store
    return new_store, 201

@app.delete("/stores/<int:store_id>")
def delete_store(store_id):
    try:
        del stores[store_id]
        return {"message": "Store deleted."}
    except KeyError:
        abort(404, message="Store not found")


@app.get("/items")
def get_items():
    return { "items" : list(items.values()) }

@app.get("/items/<int:item_id>")
def get_store_items(item_id):
    try:
        return items[item_id]
    except KeyError:
        abort(404, message="Item not found")

@app.post("/items")
def create_item():
    data = request.get_json()

    for key in ("store_id", "price", "name"):
        if key not in data:
            abort(400, message="Bad request. Include store_id, name and price.")

    if data["store_id"] not in stores:
        abort(404, message="Store not found")

    for item in items.values():
        if (
            item["name"] == data["name"] 
            and item["store_id"] == data["store_id"]
        ):
            abort(400, message="Item already exists.")    


    item_id = uuid.uuid4().hex        
    new_item = {
        **data,
        "id": item_id
    }
    items[item_id] = new_item

    return new_item, 201     

@app.put("/items/<int:item_id>")
def update_item(item_id):
    data = request.get_json()

    if item_id not in items:
        abort(404, message="Item not found.")    

    if "item_id" in data or any([x not in ("name", "price") for x in data.keys()]):
        abort(400, message="Bad request. Can only edit name and price.")    
    
    try:
        item = items[item_id] 
        item |= data
        return item
    except KeyError:
        abort(404, message="Item not found.")    

@app.delete("/items/<int:item_id>")
def delete_item(item_id):
    try:
        del items[item_id]
        return {"message": "Item deleted."}
    except KeyError:
        abort(404, message="Item not found")