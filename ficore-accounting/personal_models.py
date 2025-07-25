from datetime import datetime
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List

def sanitize_input(value: str) -> str:
    """
    Sanitize input strings to prevent injection attacks and remove harmful characters.

    Args:
        value: Input string to sanitize

    Returns:
        str: Sanitized string
    """
    import re
    if not isinstance(value, str):
        return value
    # Remove HTML tags and potentially harmful characters
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