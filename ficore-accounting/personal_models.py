from datetime import datetime
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List, Dict
from bson import ObjectId
import re
import logging
from functools import lru_cache

# Configure logger
logger = logging.getLogger('ficore_app')
logger.setLevel(logging.INFO)

def sanitize_input(value: str) -> str:
    """
    Sanitize input strings to prevent injection attacks and remove harmful characters.

    Args:
        value: Input string to sanitize

    Returns:
        str: Sanitized string
    """
    if not isinstance(value, str):
        return value
    sanitized = re.sub(r'<[^>]+>', '', value)
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
    return sanitized.strip()

class BudgetData(BaseModel):
    user_id: str
    email: EmailStr
    income: float = Field(ge=0)
    fixed_expenses: float = Field(ge=0)
    variable_expenses: float = Field(ge=0)
    savings_goal: float = Field(default=0, ge=0)
    surplus_deficit: float
    housing: float = Field(default=0, ge=0)
    food: float = Field(default=0, ge=0)
    transport: float = Field(default=0, ge=0)
    dependents: float = Field(default=0, ge=0)
    miscellaneous: float = Field(default=0, ge=0)
    others: float = Field(default=0, ge=0)
    created_at: Optional[datetime] = None

class BillData(BaseModel):
    user_id: str
    email: EmailStr
    bill_name: str
    amount: float = Field(ge=0)
    due_date: datetime
    frequency: Optional[str] = None
    category: Optional[str] = None
    status: str = Field(regex=r'^(pending|paid|overdue)$')
    send_notifications: bool = False
    send_email: bool = False
    send_sms: bool = False
    send_whatsapp: bool = False
    reminder_days: Optional[int] = None
    user_email: Optional[str] = None
    user_phone: Optional[str] = None
    first_name: Optional[str] = None

    @validator('bill_name', 'frequency', 'category', 'first_name', pre=True)
    def sanitize_text(cls, v):
        return sanitize_input(v) if v else None

class ShoppingItemData(BaseModel):
    user_id: str
    email: EmailStr
    list_id: str
    name: str
    quantity: int = Field(ge=1)
    price: float = Field(ge=0)
    category: str = Field(regex=r'^(fruits|vegetables|dairy|meat|grains|beverages|household|other)$')
    status: str = Field(regex=r'^(to_buy|bought)$')
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    store: Optional[str] = None
    frequency: int = Field(default=1, ge=1)
    unit: Optional[str] = None

    @validator('name', 'store', 'unit', pre=True)
    def sanitize_text(cls, v):
        return sanitize_input(v) if v else None

class ShoppingListData(BaseModel):
    user_id: str
    email: EmailStr
    name: str
    budget: float = Field(ge=0)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    collaborators: List[EmailStr] = []
    total_spent: float = Field(default=0, ge=0)
    status: str = Field(regex=r'^(active|ongoing|saved)$')

    @validator('name', pre=True)
    def sanitize_name(cls, v):
        return sanitize_input(v) if v else None

# Collection schemas for personal finance
personal_finance_schemas = {
    'budgets': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['user_id', 'email', 'income', 'fixed_expenses', 'variable_expenses', 'created_at'],
                'properties': {
                    'user_id': {'bsonType': 'string'},
                    'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                    'income': {'bsonType': 'double', 'minimum': 0},
                    'fixed_expenses': {'bsonType': 'double', 'minimum': 0},
                    'variable_expenses': {'bsonType': 'double', 'minimum': 0},
                    'savings_goal': {'bsonType': 'double', 'minimum': 0},
                    'surplus_deficit': {'bsonType': 'double'},
                    'housing': {'bsonType': 'double', 'minimum': 0},
                    'food': {'bsonType': 'double', 'minimum': 0},
                    'transport': {'bsonType': 'double', 'minimum': 0},
                    'dependents': {'bsonType': 'double', 'minimum': 0},
                    'miscellaneous': {'bsonType': 'double', 'minimum': 0},
                    'others': {'bsonType': 'double', 'minimum': 0},
                    'created_at': {'bsonType': 'date'}
                }
            }
        },
        'indexes': [
            {'key': [('user_id', 'ASCENDING'), ('email', 'ASCENDING'), ('created_at', 'DESCENDING')]}
        ]
    },
    'bills': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['user_id', 'email', 'bill_name', 'amount', 'due_date', 'status'],
                'properties': {
                    'user_id': {'bsonType': 'string'},
                    'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                    'bill_name': {'bsonType': 'string'},
                    'amount': {'bsonType': 'double', 'minimum': 0},
                    'due_date': {'bsonType': 'date'},
                    'frequency': {'bsonType': ['string', 'null']},
                    'category': {'bsonType': ['string', 'null']},
                    'status': {'enum': ['pending', 'paid', 'overdue']},
                    'send_notifications': {'bsonType': 'bool'},
                    'send_email': {'bsonType': 'bool'},
                    'send_sms': {'bsonType': 'bool'},
                    'send_whatsapp': {'bsonType': 'bool'},
                    'reminder_days': {'bsonType': ['int', 'null']},
                    'user_email': {'bsonType': ['string', 'null']},
                    'user_phone': {'bsonType': ['string', 'null']},
                    'first_name': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('user_id', 'ASCENDING'), ('email', 'ASCENDING'), ('due_date', 'ASCENDING')]},
            {'key': [('status', 'ASCENDING')]}
        ]
    },
    'shopping_items': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['user_id', 'email', 'list_id', 'name', 'quantity', 'price', 'category', 'status', 'created_at', 'updated_at'],
                'properties': {
                    'user_id': {'bsonType': 'string'},
                    'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                    'list_id': {'bsonType': 'string'},
                    'name': {'bsonType': 'string'},
                    'quantity': {'bsonType': 'int', 'minimum': 1},
                    'price': {'bsonType': 'double', 'minimum': 0},
                    'category': {'enum': ['fruits', 'vegetables', 'dairy', 'meat', 'grains', 'beverages', 'household', 'other']},
                    'status': {'enum': ['to_buy', 'bought']},
                    'created_at': {'bsonType': 'date'},
                    'updated_at': {'bsonType': 'date'},
                    'store': {'bsonType': ['string', 'null']},
                    'frequency': {'bsonType': 'int', 'minimum': 1},
                    'unit': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('user_id', 'ASCENDING'), ('email', 'ASCENDING'), ('list_id', 'ASCENDING')]},
            {'key': [('created_at', 'DESCENDING')]}
        ]
    },
    'shopping_lists': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['user_id', 'email', 'name', 'budget', 'created_at', 'updated_at', 'total_spent', 'status'],
                'properties': {
                    'user_id': {'bsonType': 'string'},
                    'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                    'name': {'bsonType': 'string'},
                    'budget': {'bsonType': 'double', 'minimum': 0},
                    'created_at': {'bsonType': 'date'},
                    'updated_at': {'bsonType': 'date'},
                    'collaborators': {
                        'bsonType': 'array',
                        'items': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'}
                    },
                    'total_spent': {'bsonType': 'double', 'minimum': 0},
                    'status': {'enum': ['active', 'ongoing', 'saved']}
                }
            }
        },
        'indexes': [
            {'key': [('user_id', 'ASCENDING'), ('email', 'ASCENDING'), ('status', 'ASCENDING'), ('updated_at', 'DESCENDING')]}
        ]
    }
}

@lru_cache(maxsize=128)
def get_budgets(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve budget records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of budget records

    Raises:
        RuntimeError: If database query fails
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.budgets.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error retrieving budgets: {str(e)}", 
                   exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving budgets: {str(e)}")

def create_budget(db, budget_data: dict) -> str:
    """
    Create a new budget record in the budgets collection.

    Args:
        db: MongoDB database instance
        budget_data: Dictionary containing budget information

    Returns:
        str: ID of the created budget record

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors
    """
    try:
        validated_data = BudgetData(**budget_data).dict(exclude_unset=True)
        result = db.budgets.insert_one(validated_data)
        logger.info(f"Created budget with ID: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_budgets.cache_clear()
        return str(result.inserted_id)
    except BudgetData.validation_error as e:
        logger.error(f"Invalid budget data: {str(e)}", 
                   extra={'user_id': budget_data.get('user_id', 'no-user-id'), 'email': budget_data.get('email', 'no-email')})
        raise ValueError(f"Invalid budget data: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating budget: {str(e)}", 
                   exc_info=True, extra={'user_id': budget_data.get('user_id', 'no-user-id'), 'email': budget_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating budget: {str(e)}")

def update_budget(db, budget_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a budget record in the budgets collection.

    Args:
        db: MongoDB database instance
        budget_id: ID of the budget to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails
    """
    try:
        validated_data = BudgetData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.budgets.update_one(
            {'_id': ObjectId(budget_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"Updated budget with ID: {budget_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_budgets.cache_clear()
            return True
        logger.info(f"No changes made to budget with ID: {budget_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except BudgetData.validation_error as e:
        logger.error(f"Invalid update data for budget: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid budget update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating budget with ID {budget_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating budget: {str(e)}")

def delete_budget(db, budget_id: str, user_id: str, email: str) -> bool:
    """
    Delete a budget record from the budgets collection.

    Args:
        db: MongoDB database instance
        budget_id: ID of the budget to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails
    """
    try:
        result = db.budgets.delete_one(
            {'_id': ObjectId(budget_id), 'user_id': user_id, 'email': email.lower()}
        )
        if result.deleted_count > 0:
            logger.info(f"Deleted budget with ID: {budget_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_budgets.cache_clear()
            return True
        logger.info(f"Budget not found with ID: {budget_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error deleting budget with ID {budget_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting budget: {str(e)}")

@lru_cache(maxsize=128)
def get_bills(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve bill records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of bill records

    Raises:
        RuntimeError: If database query fails
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.bills.find(filter_kwargs).sort('due_date', ASCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error retrieving bills: {str(e)}", 
                   exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving bills: {str(e)}")

def create_bill(db, bill_data: dict) -> str:
    """
    Create a new bill record in the bills collection.

    Args:
        db: MongoDB database instance
        bill_data: Dictionary containing bill information

    Returns:
        str: ID of the created bill record

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors
    """
    try:
        validated_data = BillData(**bill_data).dict(exclude_unset=True)
        result = db.bills.insert_one(validated_data)
        logger.info(f"Created bill with ID: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_bills.cache_clear()
        return str(result.inserted_id)
    except BillData.validation_error as e:
        logger.error(f"Invalid bill data: {str(e)}", 
                   extra={'user_id': bill_data.get('user_id', 'no-user-id'), 'email': bill_data.get('email', 'no-email')})
        raise ValueError(f"Invalid bill data: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating bill: {str(e)}", 
                   exc_info=True, extra={'user_id': bill_data.get('user_id', 'no-user-id'), 'email': bill_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating bill: {str(e)}")

def update_bill(db, bill_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a bill record in the bills collection.

    Args:
        db: MongoDB database instance
        bill_id: ID of the bill to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails
    """
    try:
        validated_data = BillData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.bills.update_one(
            {'_id': ObjectId(bill_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"Updated bill with ID: {bill_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_bills.cache_clear()
            return True
        logger.info(f"No changes made to bill with ID: {bill_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except ValueError as e:
        logger.error(f"Invalid update data for bill: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid bill update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating bill with ID {bill_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating bill: {str(e)}")

def delete_bill(db, bill_id: str, user_id: str, email: str) -> bool:
    """
    Delete a bill record from the bills collection.

    Args:
        db: MongoDB database instance
        bill_id: ID of the bill to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails
    """
    try:
        result = db.bills.delete_one(
            {'_id': ObjectId(bill_id), 'user_id': user_id, 'email': email.lower()}
        )
        if result.deleted_count > 0:
            logger.info(f"Deleted bill with ID: {bill_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_bills.cache_clear()
            return True
        logger.info(f"Bill not found with ID: {bill_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error deleting bill with ID {bill_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting bill: {str(e)}")

@lru_cache(maxsize=128)
def get_shopping_lists(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve shopping list records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of shopping list records

    Raises:
        RuntimeError: If database query fails
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.shopping_lists.find(filter_kwargs).sort('updated_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error retrieving shopping lists: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving shopping lists: {str(e)}")

def create_shopping_list(db, shopping_list_data: dict) -> str:
    """
    Create a new shopping list in the shopping_lists collection.

    Args:
        db: MongoDB database instance
        shopping_list_data: Dictionary containing shopping list information

    Returns:
        str: ID of the created shopping list

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors
    """
    try:
        validated_data = ShoppingListData(**shopping_list_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        result = db.shopping_lists.insert_one(validated_data)
        logger.info(f"Created shopping list with ID: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_shopping_lists.cache_clear()
        return str(result.inserted_id)
    except ShoppingListData.validation_error as e:
        logger.error(f"Invalid shopping list data: {str(e)}", 
                   extra={'user_id': shopping_list_data.get('user_id', 'no-user-id'), 'email': shopping_list_data.get('email', 'no-email')})
        raise ValueError(f"Invalid shopping list data: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating shopping list: {str(e)}", 
                    exc_info=True, extra={'user_id': shopping_list_data.get('user_id', 'no-user-id'), 'email': shopping_list_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating shopping list: {str(e)}")

def add_collaborator_to_shopping_list(db, list_id: str, user_id: str, email: str, collaborator_email: str) -> bool:
    """
    Add a collaborator to a shopping list.

    Args:
        db: MongoDB database instance
        list_id: ID of the shopping list
        user_id: ID of the user
        email: Email address of the user
        collaborator_email: Email address of the collaborator to add

    Returns:
        bool: True if collaborator added, False if already exists or not found

    Raises:
        ValueError: If collaborator email is invalid
        RuntimeError: If update fails
    """
    try:
        collaborator_email = collaborator_email.lower()
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', collaborator_email):
            raise ValueError("Invalid collaborator email")
        
        result = db.shopping_lists.update_one(
            {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
            {'$addToSet': {'collaborators': collaborator_email}, '$set': {'updated_at': datetime.utcnow()}}
        )
        if result.modified_count > 0:
            logger.info(f"Added collaborator {collaborator_email} to shopping list {list_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_shopping_lists.cache_clear()
            return True
        logger.info(f"No changes made to shopping list {list_id} for collaborator {collaborator_email}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except ValueError as e:
        logger.error(f"Invalid collaborator email: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise
    except Exception as e:
        logger.error(f"Error adding collaborator to shopping list {list_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error adding collaborator: {str(e)}")

def remove_collaborator_from_shopping_list(db, list_id: str, user_id: str, email: str, collaborator_email: str) -> bool:
    """
    Remove a collaborator from a shopping list.

    Args:
        db: MongoDB database instance
        list_id: ID of the shopping list
        user_id: ID of the user
        email: Email address of the user
        collaborator_email: Email address of the collaborator to remove

    Returns:
        bool: True if collaborator removed, False if not found or no changes made

    Raises:
        RuntimeError: If update fails
    """
    try:
        result = db.shopping_lists.update_one(
            {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
            {'$pull': {'collaborators': collaborator_email.lower()}, '$set': {'updated_at': datetime.utcnow()}}
        )
        if result.modified_count > 0:
            logger.info(f"Removed collaborator {collaborator_email} from shopping list {list_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_shopping_lists.cache_clear()
            return True
        logger.info(f"No changes made to shopping list {list_id} for collaborator {collaborator_email}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error removing collaborator from shopping list {list_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error removing collaborator: {str(e)}")

def update_shopping_list(db, list_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a shopping list in the shopping_lists collection.

    Args:
        db: MongoDB database instance
        list_id: ID of the shopping list to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails
    """
    try:
        validated_data = ShoppingListData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.shopping_lists.update_one(
            {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"Updated shopping list with ID: {list_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_shopping_lists.cache_clear()
            return True
        logger.info(f"No changes made to shopping list with ID: {list_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except ShoppingListData.validation_error as e:
        logger.error(f"Invalid update data for shopping list: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid shopping list update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating shopping list with ID {list_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating shopping list: {str(e)}")

def delete_shopping_list(db, list_id: str, user_id: str, email: str) -> bool:
    """
    Delete a shopping list and its associated items from the shopping_lists collection.

    Args:
        db: MongoDB database instance
        list_id: ID of the shopping list to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails
    """
    try:
        with db.client.start_session() as session:
            with session.start_transaction():
                db.shopping_items.delete_many({'list_id': list_id, 'user_id': user_id, 'email': email.lower()}, session=session)
                result = db.shopping_lists.delete_one(
                    {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if result.deleted_count > 0:
                    logger.info(f"Deleted shopping list with ID: {list_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_shopping_lists.cache_clear()
                    get_shopping_items.cache_clear()
                    return True
                logger.info(f"Shopping list not found with ID: {list_id}", 
                           extra={'user_id': user_id, 'email': email})
                return False
    except Exception as e:
        logger.error(f"Error deleting shopping list with ID {list_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting shopping list: {str(e)}")

@lru_cache(maxsize=128)
def get_shopping_items(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve shopping item records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of shopping item records

    Raises:
        RuntimeError: If database query fails
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.shopping_items.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"Error retrieving shopping items: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving shopping items: {str(e)}")

def create_shopping_item(db, shopping_item_data: dict) -> str:
    """
    Create a new shopping item in the shopping_items collection and update total_spent in shopping_lists.

    Args:
        db: MongoDB database instance
        shopping_item_data: Dictionary containing shopping item information

    Returns:
        str: ID of the created shopping item

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors
    """
    try:
        validated_data = ShoppingItemData(**shopping_item_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        
        with db.client.start_session() as session:
            with session.start_transaction():
                result = db.shopping_items.insert_one(validated_data, session=session)
                if validated_data['status'] == 'bought':
                    db.shopping_lists.update_one(
                        {'_id': ObjectId(validated_data['list_id']), 'user_id': validated_data['user_id'], 'email': validated_data['email'].lower()},
                        {'$inc': {'total_spent': validated_data['price'] * validated_data['quantity']}, '$set': {'updated_at': datetime.utcnow()}},
                        session=session
                    )
                logger.info(f"Created shopping item with ID: {result.inserted_id}", 
                           extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
                get_shopping_items.cache_clear()
                get_shopping_lists.cache_clear()
                return str(result.inserted_id)
    except ShoppingItemData.validation_error as e:
        logger.error(f"Invalid shopping item data: {str(e)}", 
                   extra={'user_id': shopping_item_data.get('user_id', 'no-user-id'), 'email': shopping_item_data.get('email', 'no-email')})
        raise ValueError(f"Invalid shopping item data: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating shopping item: {str(e)}", 
                    exc_info=True, extra={'user_id': shopping_item_data.get('user_id', 'no-user-id'), 'email': shopping_item_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating shopping item: {str(e)}")

def update_shopping_item(db, item_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a shopping item in the shopping_items collection and recalculate total_spent in shopping_lists.

    Args:
        db: MongoDB database instance
        item_id: ID of the shopping item to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails
    """
    try:
        validated_data = ShoppingItemData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        
        with db.client.start_session() as session:
            with session.start_transaction():
                current_item = db.shopping_items.find_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if not current_item:
                    logger.info(f"Shopping item not found with ID: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    return False
                
                result = db.shopping_items.update_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    {'$set': validated_data},
                    session=session
                )
                
                if result.modified_count > 0:
                    old_amount = current_item['price'] * current_item['quantity'] if current_item['status'] == 'bought' else 0
                    new_amount = validated_data['price'] * validated_data['quantity'] if validated_data['status'] == 'bought' else 0
                    amount_diff = new_amount - old_amount
                    
                    if amount_diff != 0:
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(validated_data['list_id']), 'user_id': user_id, 'email': email.lower()},
                            {'$inc': {'total_spent': amount_diff}, '$set': {'updated_at': datetime.utcnow()}},
                            session=session
                        )
                    
                    logger.info(f"Updated shopping item with ID: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_shopping_items.cache_clear()
                    get_shopping_lists.cache_clear()
                    return True
                logger.info(f"No changes made to shopping item with ID: {item_id}", 
                           extra={'user_id': user_id, 'email': email})
                return False
    except ShoppingItemData.validation_error as e:
        logger.error(f"Invalid update data for shopping item: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid shopping item update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating shopping item with ID {item_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating shopping item: {str(e)}")

def delete_shopping_item(db, item_id: str, user_id: str, email: str) -> bool:
    """
    Delete a shopping item from the shopping_items collection and update total_spent in shopping_lists.

    Args:
        db: MongoDB database instance
        item_id: ID of the shopping item to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails
    """
    try:
        with db.client.start_session() as session:
            with session.start_transaction():
                item = db.shopping_items.find_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if not item:
                    logger.info(f"Shopping item not found with ID: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    return False
                
                result = db.shopping_items.delete_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                
                if result.deleted_count > 0:
                    if item['status'] == 'bought':
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(item['list_id']), 'user_id': user_id, 'email': email.lower()},
                            {'$inc': {'total_spent': -(item['price'] * item['quantity'])}, '$set': {'updated_at': datetime.utcnow()}},
                            session=session
                        )
                    logger.info(f"Deleted shopping item with ID: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_shopping_items.cache_clear()
                    get_shopping_lists.cache_clear()
                    return True
                return False
    except Exception as e:
        logger.error(f"Error deleting shopping item with ID {item_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting shopping item: {str(e)}")
