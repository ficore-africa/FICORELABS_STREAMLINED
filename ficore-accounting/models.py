from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError, OperationFailure
from werkzeug.security import generate_password_hash
from bson import ObjectId
import logging
import re
from translations import trans
from utils import get_mongo_db, logger
from functools import lru_cache
import traceback
import time
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List, Union, Dict
from decimal import Decimal

# Configure logger for the application
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
    # Remove HTML tags and potentially harmful characters
    sanitized = re.sub(r'<[^>]+>', '', value)
    sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
    return sanitized.strip()

class UserData(BaseModel):
    email: EmailStr
    password: str
    role: str = Field(default='personal', pattern=r'^(personal|trader|agent|admin)$')
    display_name: Optional[str] = None
    is_admin: bool = False
    setup_complete: bool = False
    coin_balance: int = Field(default=10, ge=0)
    ficore_credit_balance: int = Field(default=0, ge=0)
    language: str = Field(default='en', regex=r'^(en|ha)$')
    dark_mode: bool = False
    created_at: Optional[datetime] = None
    business_details: Optional[Dict] = None
    personal_details: Optional[Dict] = None
    agent_details: Optional[Dict] = None

    @validator('display_name', pre=True)
    def sanitize_display_name(cls, v):
        return sanitize_input(v) if v else None

class RecordData(BaseModel):
    user_id: str
    email: EmailStr
    type: str = Field(regex=r'^(debtor|creditor)$')
    name: str
    contact: Optional[str] = None
    amount_owed: float = Field(ge=0)
    description: Optional[str] = None
    reminder_count: int = Field(default=0, ge=0)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @validator('name', 'description', pre=True)
    def sanitize_text(cls, v):
        return sanitize_input(v) if v else None

class CashflowData(BaseModel):
    user_id: str
    email: EmailStr
    type: str = Field(regex=r'^(receipt|payment)$')
    party_name: str
    amount: float = Field(ge=0)
    method: Optional[str] = None
    category: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @validator('party_name', 'method', 'category', pre=True)
    def sanitize_text(cls, v):
        return sanitize_input(v) if v else None

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

class AgentData(BaseModel):
    agent_id: str = Field(regex=r'^[A-Z0-9]{8}$')
    email: EmailStr
    status: str = Field(regex=r'^(active|inactive)$')
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

def get_db():
    """
    Get MongoDB database connection using the global client from utils.py.
    
    Returns:
        Database object
    
    Raises:
        RuntimeError: If database connection fails
    """
    try:
        db = get_mongo_db()
        logger.info(f"Successfully connected to MongoDB database: {db.name}", extra={'user_id': 'no-user-id', 'email': 'no-email'})
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}", exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Database connection failed: {str(e)}")

def initialize_app_data(app):
    """
    Initialize MongoDB collections and indexes.
    
    Args:
        app: Flask application instance
    
    Raises:
        RuntimeError: If database initialization fails
    """
    max_retries = 3
    retry_delay = 1
    
    with app.app_context():
        for attempt in range(max_retries):
            try:
                db = get_db()
                db.command('ping')
                logger.info(f"Attempt {attempt + 1}/{max_retries} - {trans('general_database_connection_established', default='MongoDB connection established')}", 
                           extra={'user_id': 'no-user-id', 'email': 'no-email'})
                break
            except Exception as e:
                logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {str(e)}", 
                            exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                if attempt == max_retries - 1:
                    raise RuntimeError(trans('general_database_connection_failed', default='MongoDB connection failed after max retries'))
                time.sleep(retry_delay)
        
        try:
            db_instance = get_db()
            logger.info(f"MongoDB database: {db_instance.name}", extra={'user_id': 'no-user-id', 'email': 'no-email'})
            collections = db_instance.list_collection_names()
            
            # Define collection schemas
            collection_schemas = {
                'users': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'email', 'password_hash', 'role'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'password_hash': {'bsonType': 'string'},
                                'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                                'coin_balance': {'bsonType': 'int', 'minimum': 0},
                                'ficore_credit_balance': {'bsonType': 'int', 'minimum': 0},
                                'language': {'enum': ['en', 'ha']},
                                'created_at': {'bsonType': 'date'},
                                'display_name': {'bsonType': ['string', 'null']},
                                'is_admin': {'bsonType': 'bool'},
                                'setup_complete': {'bsonType': 'bool'},
                                'reset_token': {'bsonType': ['string', 'null']},
                                'reset_token_expiry': {'bsonType': ['date', 'null']},
                                'otp': {'bsonType': ['string', 'null']},
                                'otp_expiry': {'bsonType': ['date', 'null']},
                                'business_details': {
                                    'bsonType': ['object', 'null'],
                                    'properties': {
                                        'name': {'bsonType': 'string'},
                                        'address': {'bsonType': 'string'},
                                        'industry': {'bsonType': 'string'},
                                        'products_services': {'bsonType': 'string'},
                                        'phone_number': {'bsonType': 'string'}
                                    }
                                },
                                'personal_details': {
                                    'bsonType': ['object', 'null'],
                                    'properties': {
                                        'first_name': {'bsonType': 'string'},
                                        'last_name': {'bsonType': 'string'},
                                        'phone_number': {'bsonType': 'string'},
                                        'address': {'bsonType': 'string'}
                                    }
                                },
                                'agent_details': {
                                    'bsonType': ['object', 'null'],
                                    'properties': {
                                        'agent_name': {'bsonType': 'string'},
                                        'agent_id': {'bsonType': 'string'},
                                        'area': {'bsonType': 'string'},
                                        'role': {'bsonType': 'string'},
                                        'email': {'bsonType': 'string'},
                                        'phone': {'bsonType': 'string'}
                                    }
                                }
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('email', ASCENDING)], 'unique': True},
                        {'key': [('reset_token', ASCENDING)], 'sparse': True},
                        {'key': [('role', ASCENDING)]}
                    ]
                },
                'records': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'type', 'name', 'amount_owed'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'type': {'enum': ['debtor', 'creditor']},
                                'name': {'bsonType': 'string'},
                                'contact': {'bsonType': ['string', 'null']},
                                'amount_owed': {'bsonType': 'double', 'minimum': 0},
                                'description': {'bsonType': ['string', 'null']},
                                'reminder_count': {'bsonType': 'int', 'minimum': 0},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('type', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'cashflows': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'type', 'party_name', 'amount'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'type': {'enum': ['receipt', 'payment']},
                                'party_name': {'bsonType': 'string'},
                                'amount': {'bsonType': 'double', 'minimum': 0},
                                'method': {'bsonType': ['string', 'null']},
                                'category': {'bsonType': ['string', 'null']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('type', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'ficore_credit_transactions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'amount', 'type', 'date'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'amount': {'bsonType': 'int'},
                                'type': {'enum': ['add', 'spend', 'purchase', 'admin_credit', 'create_shopping_list']},
                                'ref': {'bsonType': ['string', 'null']},
                                'date': {'bsonType': 'date'},
                                'facilitated_by_agent': {'bsonType': ['string', 'null']},
                                'payment_method': {'bsonType': ['string', 'null']},
                                'cash_amount': {'bsonType': ['double', 'null']},
                                'notes': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING)]},
                        {'key': [('date', DESCENDING)]}
                    ]
                },
                'credit_requests': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'amount', 'payment_method', 'status', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'amount': {'bsonType': 'int', 'minimum': 1},
                                'payment_method': {'enum': ['card', 'cash', 'bank']},
                                'receipt_file_id': {'bsonType': ['objectId', 'null']},
                                'status': {'enum': ['pending', 'approved', 'denied']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']},
                                'admin_id': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING)]},
                        {'key': [('status', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'audit_logs': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['admin_id', 'email', 'action', 'timestamp'],
                            'properties': {
                                'admin_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'action': {'bsonType': 'string'},
                                'details': {'bsonType': ['object', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('admin_id', ASCENDING), ('email', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                },
                'agents': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'email', 'status', 'created_at'],
                            'properties': {
                                '_id': {'bsonType': 'string', 'pattern': r'^[A-Z0-9]{8}$'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'status': {'enum': ['active', 'inactive']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('email', ASCENDING)], 'unique': True},
                        {'key': [('status', ASCENDING)]}
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
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('list_id', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
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
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('status', ASCENDING), ('updated_at', DESCENDING)]}
                    ]
                },
                'feedback': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'tool_name', 'rating', 'timestamp'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'tool_name': {'bsonType': 'string'},
                                'rating': {'bsonType': 'int', 'minimum': 1, 'maximum': 5},
                                'comment': {'bsonType': ['string', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                },
                'tool_usage': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'tool_name', 'timestamp'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'tool_name': {'bsonType': 'string'},
                                'action': {'bsonType': ['string', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING)]},
                        {'key': [('tool_name', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                },
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
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('created_at', DESCENDING)]}
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
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('due_date', ASCENDING)]},
                        {'key': [('status', ASCENDING)]}
                    ]
                },
                'bill_reminders': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'email', 'notification_id', 'type', 'message', 'sent_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'notification_id': {'bsonType': 'string'},
                                'type': {'enum': ['email', 'sms', 'whatsapp']},
                                'message': {'bsonType': 'string'},
                                'sent_at': {'bsonType': 'date'},
                                'read_status': {'bsonType': 'bool'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('email', ASCENDING), ('sent_at', DESCENDING)]}
                    ]
                },
                'system_config': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'value'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'value': {'bsonType': ['bool', 'string', 'int', 'double', 'date', 'object', 'array']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('_id', ASCENDING)], 'unique': True}
                    ]
                }
            }
            
            # Initialize collections and indexes
            for collection_name, config in collection_schemas.items():
                if collection_name == 'credit_requests' and collection_name in collections:
                    try:
                        db_instance.command('collMod', collection_name, validator=config.get('validator', {}))
                        logger.info(f"Updated validator for collection: {collection_name}", 
                                    extra={'user_id': 'no-user-id', 'email': 'no-email'})
                    except Exception as e:
                        logger.error(f"Failed to update validator for collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                        raise
                elif collection_name not in collections:
                    try:
                        db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                        logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}", 
                                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
                    except Exception as e:
                        logger.error(f"Failed to create collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                        raise
                
                existing_indexes = db_instance[collection_name].index_information()
                for index in config.get('indexes', []):
                    keys = index['key']
                    options = {k: v for k, v in index.items() if k != 'key'}
                    index_key_tuple = tuple(keys)
                    index_name = '_'.join(f"{k}_{v if isinstance(v, int) else str(v).replace(' ', '_')}" for k, v in keys)
                    
                    # Skip if the index includes _id
                    if any(key[0] == '_id' for key in keys):
                        logger.info(f"Skipping creation of index involving _id on {collection_name}: {keys}", 
                                    extra={'user_id': 'no-user-id', 'email': 'no-email'})
                        continue
                    
                    index_exists = False
                    for existing_index_name, existing_index_info in existing_indexes.items():
                        if tuple(existing_index_info['key']) == index_key_tuple:
                            existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                            if existing_options == options:
                                logger.info(f"{trans('general_index_exists', default='Index already exists on')} {collection_name}: {keys} with options {options}", 
                                           extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                index_exists = True
                            else:
                                if existing_index_name == '_id_':
                                    logger.info(f"Skipping drop of _id index on {collection_name}", 
                                               extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                    continue
                                try:
                                    db_instance[collection_name].drop_index(existing_index_name)
                                    logger.info(f"Dropped conflicting index {existing_index_name} on {collection_name}", 
                                               extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                except Exception as e:
                                    logger.error(f"Failed to drop index {existing_index_name} on {collection_name}: {str(e)}", 
                                                exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                    raise
                            break
                    if not index_exists:
                        try:
                            db_instance[collection_name].create_index(keys, name=index_name, **options)
                            logger.info(f"{trans('general_index_created', {'collection_name': collection_name, 'keys': keys})}", 
                                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
                        except Exception as e:
                            if 'IndexKeySpecsConflict' in str(e):
                                logger.info(f"Attempting to resolve index conflict for {collection_name}: {index_name}", 
                                    extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                if index_name != '_id_':
                                    db_instance[collection_name].drop_index(index_name)
                                    db_instance[collection_name].create_index(keys, name=index_name, **options)
                                    logger.info(f"Recreated index on {collection_name}: {keys} with options {options}", 
                                           extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                else:
                                    logger.info(f"Skipping recreation of _id index on {collection_name}", 
                                           extra={'user_id': 'no-user-id', 'email': 'no-email'})
                            else:
                                logger.error(f"Failed to create index on {collection_name}: {str(e)}", 
                                        exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                                raise
            
            # Initialize agents
            agents_collection = db_instance.agents
            if agents_collection.count_documents({}) == 0:
                try:
                    agent_data = AgentData(
                        agent_id='AG123456',
                        email='agent@example.com',
                        status='active',
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    agents_collection.insert_one(agent_data.dict(exclude_unset=True))
                    logger.info(trans('general_agents_initialized', default='Initialized agents in MongoDB'), 
                               extra={'user_id': 'no-user-id', 'email': 'no-email'})
                except Exception as e:
                    logger.error(f"Failed to insert sample agents: {str(e)}", exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
                    raise
            
        except Exception as e:
            logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}", 
                        exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
            raise

class User:
    """
    Represents a user in the system.

    Attributes:
        id (str): Unique user identifier
        email (str): User's email address
        username (str): User's username
        role (str): User's role (personal, trader, agent, admin)
        display_name (str): User's display name
        is_admin (bool): Whether the user is an admin
        setup_complete (bool): Whether user setup is complete
        coin_balance (int): User's coin balance
        ficore_credit_balance (int): User's fiscal credit balance
        language (str): User's preferred language
        dark_mode (bool): Whether dark mode is enabled
    """
    def __init__(self, id: str, email: str, display_name: Optional[str]=None, role: str='personal', 
                 username: Optional[str]=None, is_admin: bool=False, setup_complete: bool=False, 
                 coin_balance: int=0, ficore_credit_balance: int=0, language: str='en', dark_mode: bool=False):
        self.id = id
        self.email = email
        self.username = username or display_name or email.split('@')[0]
        self.role = role
        self.display_name = display_name or self.username
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.coin_balance = coin_balance
        self.ficore_credit_balance = ficore_credit_balance
        self.language = language
        self.dark_mode = dark_mode

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_active(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)

    def get(self, key: str, default=None):
        return getattr(self, key, default)

def create_user(db, user_data: dict) -> User:
    """
    Create a new user in the users collection.

    Args:
        db: MongoDB database instance
        user_data: Dictionary containing user information

    Returns:
        User: Created user object

    Raises:
        ValueError: If email or user ID already exists or validation fails
        RuntimeError: For other database errors

    Example:
        user_data = {
            'email': 'user@example.com',
            'password': 'securepass123',
            'role': 'personal',
            'display_name': 'John Doe'
        }
        user = create_user(db, user_data)
    """
    try:
        validated_data = UserData(**user_data).dict(exclude_unset=True)
        user_id = validated_data.get('username', validated_data['email'].split('@')[0]).lower()
        
        if 'password' in validated_data:
            validated_data['password_hash'] = generate_password_hash(validated_data.pop('password'))
        
        user_doc = {
            '_id': user_id,
            'email': validated_data['email'].lower(),
            'password_hash': validated_data.get('password_hash'),
            'role': validated_data.get('role'),
            'display_name': validated_data.get('display_name'),
            'is_admin': validated_data.get('is_admin'),
            'setup_complete': validated_data.get('setup_complete'),
            'coin_balance': validated_data.get('coin_balance'),
            'ficore_credit_balance': validated_data.get('ficore_credit_balance'),
            'language': validated_data.get('language'),
            'dark_mode': validated_data.get('dark_mode'),
            'created_at': validated_data.get('created_at', datetime.utcnow()),
            'business_details': validated_data.get('business_details'),
            'personal_details': validated_data.get('personal_details'),
            'agent_details': validated_data.get('agent_details')
        }
        
        db.users.insert_one(user_doc)
        logger.info(f"{trans('general_user_created', default='Created user with ID')}: {user_id}", 
                   extra={'user_id': user_id, 'email': validated_data['email']})
        get_user.cache_clear()
        get_user_by_email.cache_clear()
        return User(
            id=user_doc['_id'],
            email=user_doc['email'],
            username=user_doc['_id'],
            role=user_doc['role'],
            display_name=user_doc['display_name'],
            is_admin=user_doc['is_admin'],
            setup_complete=user_doc['setup_complete'],
            coin_balance=user_doc['coin_balance'],
            ficore_credit_balance=user_doc['ficore_credit_balance'],
            language=user_doc['language'],
            dark_mode=user_doc['dark_mode']
        )
    except UserData.validation_error as e:
        logger.error(f"Validation error creating user: {str(e)}", 
                   extra={'user_id': 'no-user-id', 'email': user_data.get('email', '')}, exc_info=True)
        raise ValueError(f"Invalid user data: {str(e)}")
    except DuplicateKeyError:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: DuplicateKeyError", 
                   extra={'user_id': 'no-user-id', 'email': user_data.get('email', '')}, exc_info=True)
        raise ValueError('general_trans'('exists', default='User with this email or username already exists'))
    except Exception as e:
        logger.error(f"{trans('general_user_creation_error', default='Error creating user')}: {str(e)}", 
                   extra={'user_id': 'no-user-id', 'email': user_data.get('email', '')}, exc_info=True)
        raise RuntimeError(f"Error creating user: {str(e)}")

@lru_cache(maxsize=128)
def get_user_by_email(db, email: str) -> Optional[User]:
    """
    Retrieve a user by email from the users collection.

    Args:
        db: MongoDB database instance
        email: Email address of the user

    Returns:
        User: User object or None if not found

    Raises:
        RuntimeError: If database query fails

    Example:
        user = get_user_by_email(db, email='user@example.com')
    """
    try:
        logger.debug(f"Calling get_user_by_email for email: {email}, stack: {''.join(traceback.format_stack()[-5:])}", 
                    extra={'user_id': 'no-user-id', 'email': email})
        user_doc = db.users.find_one({'_email': email.lower()})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                username=user_doc['_id'],
                role=user_doc.get('user_doc', 'personal'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                coin_balance=user_doc.get('coin_balance', 0),
                ficore_credit_balance=user_doc.get('ficore_credit_balance', 0),
                language=user_doc.get('language', ''),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by email')} {email}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': email})
        raise RuntimeError(f"Error retrieving user by email: {str(e)}")

@lru_cache(maxsize=128)
def get_user(db, user_id: str, email: Optional[str]=None) -> Optional[User]:
    """
    Retrieve a user by ID and email from the users collection.

    Args:
        db: MongoDB database instance
        user_id: ID of the user
        email: Optional email address to filter the user

    Returns:
        User: User object or None if not found

    Raises:
        Exception: RuntimeError if database query fails

    Example:
        user = get_user(db, user_id='user123', email='user@example.com')
    """
    try:
        logger.debug(f"Calling get_user_id for user_id: {user_id}, email: {email}, stack: {''.join(traceback.format_stack()[-5:])}", 
                    extra={'user_id': user_id, 'email': email or 'no-email'})
        query = {'user_id': '_id'}
        if email:
            query['email'] = email.lower()
        user_doc = db.users.find_one(query)
        if user_doc:
            return User(
                user_id=user_doc['_id'],
                email=user_doc['email'],
                username=user_doc['_id'],
                role=user_doc.get('user_doc', 'personal'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                coin_balance=user_doc.get('coin_balance', 0),
                ficore_credit_balance=user_doc.get('ficore_credit_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False),
                
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user_id by ID')} {user_id}, email: {email}: {str(e)}", 
                    extra={'user_id': user_id, 'email': email or 'no-email'}, exc_info=True)
        raise RuntimeError(f"Error retrieving user: {str(e)}")

def delete_user(db, user_id: str, email: str) -> bool:
    """
    Delete a user and their associated data from the users collection.

    Args:
        db: MongoDB database instance
        user_id: ID of the user to delete
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If database deletion fails

    Example:
        deleted = delete_user(db, user_id='user123', email='user@example.com')
    """
    try:
        with db.client.start_session() as session:
            with session.start_transaction():
                # Delete related data from other collections
                collections_to_clean = [
                    'records',
                    'cashflows',
                    'ficore_credit_transactions',
                    'credit_requests',
                    'audit_logs',
                    'shopping_items',
                    'shopping_lists',
                    'budgets',
                    'bills',
                    'bill_reminders',
                    'feedback',
                    'tool_usage'
                ]
                for collection in collections_to_clean:
                    db[collection].delete_many({{'user_id': user_id, 'email': email.lower()}}, session=session)
                    logger.info(f"Deleted related data from {collection} for user {user_id}", 
                               extra={'user_id': user_id, 'email': email})
                
                # Delete the user
                result = db.users.delete_one({'_id': user_id, 'email': email.lower()}, session=session)
                if result.deleted_count > 0:
                    logger.info(f"{trans('general_user_deleted', default='Deleted user with ID')}: {user_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_user.cache_clear()
                    get_user_by_email.cache_clear()
                    return True
                logger.info(f"{trans('general_user_not_found', default='User not found with ID')}: {user_id}", 
                           extra={'user_id': user_id, 'email': email})
                return False
    except Exception as e:
        logger.error(f"{trans('general_user_delete_error', default='Error deleting user with ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting user: {str(e)}")

def check_ficore_credit_balance(db, user_id: str, email: str, required_amount: int) -> bool:
    """
    Check if a user has sufficient credit balance.

    Args:
        db: MongoDB database instance
        user_id: ID of the user
        email: Email address of the user
        required_amount: Required credit amount

    Returns:
        bool: True if sufficient balance, False otherwise

    Raises:
        RuntimeError: If database query fails

    Example:
        sufficient = check_ficore_credit_balance(db, user_id='user123', email='user@example.com', required_amount=100)
    """
    try:
        user = db.users.find_one({'_id': user_id, 'email': email.lower()})
        if not user:
            logger.info(f"User not found for ID {user_id}, email: {email}", extra={'user_id': user_id, 'email': email})
            return False
        balance = user.get('ficore_credit_balance', 0)
        sufficient = balance >= required_amount
        logger.info(f"Checked credit balance for user {user_id}, email: {email}. Balance: {balance}, Required: {required_amount}, Sufficient: {sufficient}", 
                   extra={'user_id': user_id, 'email': email})
        return sufficient
    except Exception as e:
        logger.error(f"Error checking credit balance for user {user_id}, email: {email}: {str(e)}", 
                   exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error checking credit balance: {str(e)}")

def create_credit_request(db, request_data: dict) -> str:
    """
    Create a new credit request in the credit_requests collection.

    Args:
        db: MongoDB database instance
        request_data: Dictionary containing credit request information

    Returns:
        str: ID of the created credit request

    Raises:
        ValueError: If required fields are missing
        RuntimeError: For other database errors

    Example:
        request_data = {
            'user_id': 'user123',
            'email': 'user@example.com',
            'amount': 100,
            'payment_method': 'card',
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        request_id = create_credit_request(db, request_data)
    """
    try:
        required_fields = ['user_id', 'email', 'amount', 'payment_method', 'status', 'created_at']
        if not all(field in request_data for field in required_fields):
            raise ValueError(trans('credits_missing_request_fields', default='Missing required credit request fields'))
        request_data['email'] = request_data['email'].lower()
        result = db.credit_requests.insert_one(request_data)
        logger.info(f"{trans('credits_request_created', default='Created credit request with ID')}: {result.inserted_id}", 
                   extra={'user_id': request_data.get('user_id', 'no-user-id'), 'email': request_data.get('email', 'no-email')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('credits_request_creation_error', default='Error creating credit request')}: {str(e)}", 
                    exc_info=True, extra={'user_id': request_data.get('user_id', 'no-user-id'), 'email': request_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating credit request: {str(e)}")

def update_credit_request(db, request_id: str, update_data: dict) -> bool:
    """
    Update a credit request in the credit_requests collection.

    Args:
        db: MongoDB database instance
        request_id: The ID of the credit request to update
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        RuntimeError: If database update fails

    Example:
        update_data = {'status': 'approved', 'admin_id': 'admin123'}
        updated = update_credit_request(db, request_id='1234567890', update_data=update_data)
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.credit_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('credits_request_updated', default='Updated credit request with ID')}: {request_id}", 
                       extra={'user_id': 'no-user-id', 'email': 'no-email'})
            return True
        logger.info(f"{trans('credits_request_no_change', default='No changes made to credit request with ID')}: {request_id}", 
                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
        return False
    except Exception as e:
        logger.error(f"{trans('credits_request_update_error', default='Error updating credit request with ID')} {request_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error updating credit request: {str(e)}")

def get_credit_requests(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve credit request records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return

    Returns:
        list: List of credit request records

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com'}
        records = get_credit_requests(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.credit_requests.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('credits_requests_fetch_error', default='Error getting credit requests')}: {str(e)}", 
                    extra={'user_id': 'no-user-id', 'email': 'no-email'}, exc_info=True)
        raise RuntimeError(f"Error retrieving credit requests: {str(e)}")

def to_dict_credit_request(record_data: Optional[dict]) -> dict:
    """
    Convert a credit request to a dictionary format.

    Args:
        record: Credit request document or None

    Returns:
        dict: Dictionary representation of the credit request

    Example:
        credit_request = db.credit_requests.find_one({'_id': ObjectId('123456789012345678901234')})
        dict_request = to_dict_credit_request(credit_request)
    """
    if not record_data:
        return {'user_id': None, 'email': None, 'amount': None, 'status': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'email': record.get('email', ''),
        'amount': record.get('amount', 0),
        'payment_method': record.get('payment_method', ''),
        'receipt_file_id': str(record.get('receipt_file_id', '')) if record.get('receipt_file_id') else None,
        'status': record.get('status', ''),
        'created_at': record.get('created_at', ''),
        'updated_at': record.get('updated_at'),
        'admin_id': record.get('admin_id')
    }

def create_agent(db, agent_data: dict) -> str:
    """
    Creates a new agent in the system in the Agents collection.

    Args:
        db: MongoDB instance database
        agent_data: Dictionary that contains agent information

    Returns:
        str: ID of the created

    Raises:
        ValueError: If validation fails or agent ID/email already exists
        RuntimeError: For other database errors

    Example:
        agent_data = {
            'agent_id': 'AG123456',
            'email': 'agent@example.com',
            'status': 'active',
            'created_at': datetime.utcnow()
        }
        agent_id = create_agent(db, agent_data)
    """
    try:
        validated_data = agent_data(**AgentData).dict(exclude_unset=True)
        agent_doc = {
            '_id': validated_data['agent_id'].upper(),
            'email': validated_data['email'].lower(),
            'status': validated_data.get('status'),
            'created_at': validated_data.get('created_at', datetime.utcnow()),
            'updated_at': validated_data.get('updated_at')
        }
        result = db.agents.insert_one(agent_doc)
        logger.info(f"{trans('general_agent_created', default='Created agent with ID')}: {result.inserted_id}", 
                   extra={'agent_id': agent_doc['_id'], 'email': agent_doc['email']})
        return agent_doc['_id']
    except AgentData.validation_error() as e:
        logger.error(f"Validation error creating agent: {str(e)}", 
                    extra={'agent_id': 'no-agent-id', 'email': agent_data.get('email', '')}, exc_info=True)
        raise ValueError(f"Invalid agent data: {str(e)}")
    except DuplicateKeyError:
        logger.error(f"{trans('general_agent_creation_error', default='Error creating agent')}: DuplicateKeyError", 
                    extra={'agent_id': 'no-agent-id', 'email': agent_data.get('email', '')}, exc_info=True)
        raise ValueError(trans('general_agent_exists', default='Agent with this ID or email already exists'))
    except Exception as e:
        logger.error(f"{trans('general_agent_creation_error', default='Error creating agent')}: {str(e)}", 
                    extra={'agent_id': 'no-agent-id', 'email': agent_data.get('email', '')}, exc_info=True)
        raise RuntimeError(f"Error creating agent: {str(e)}")

def get_agent(db, agent_id: str, email: Optional[str]=None) -> Optional[dict]:
    """
    Retrieve an agent by ID and email from the agents collection.

    Args:
        db: MongoDB database instance
        agent_id: The agent ID to retrieve
        email: Email address of the agent (optional)

    Returns:
        dict: Agent document or None if not found

    Raises:
        RuntimeError: If database query fails

    Example:
        agent = get_agent(db, agent_id='AG123456', email='agent@example.com')
    """
    try:
        query = {'_id': agent_id.upper()}
        if email:
            query['email'] = email.lower()
        agent_doc = db.agents.find_one(query)
        if agent_doc:
            return {
                '_id': agent_doc['_id'],
                'email': agent_doc['email'],
                'status': agent_doc['status'],
                'created_at': agent_doc['created_at'],
                'updated_at': agent_doc.get('updated_at')
            }
        return None
    except Exception as e:
        logger.error(f"{trans('agents_fetch_error', default='Error getting agent by ID')} {agent_id}, email: {email}: {str(e)}", 
                    extra={'user_id': 'no-user-id', 'email': email or 'no-email'}, exc_info=True)
        raise RuntimeError(f"Error retrieving agent: {str(e)}")

def update_agent(db, agent_id: str, email: str, status: str) -> bool:
    """
    Update an agent's status in the Agents collection.

    Args:
        db: MongoDB instance database
        agent_id: The agent to update
        email: Email address of agent
        status: New status ('active' or 'inactive')

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If status is invalid
        RuntimeError: If database update fails

    Example:
        Updated = update_agent(db, agent_id='AG123456', email='agent@example.com', status='active')
    """
    try:
        if status not in ['active', 'inactive']:
            raise ValueError('Invalid status value')
        result = db.agents.update_one(
            {'_id': agent_id.upper(), 'email': email.lower()},
            {'$set': {'status': status}, '$updated_at': datetime.utcnow()}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('agents_status_updated', default='Updated agent status for ID')}: {agent_id}", 
                   extra={'user_id': 'no-user-id', 'email': email})
            return True
        logger.info(f"No changes made to agent {agent_id}", 
                    extra={'user_id': 'no-user-id', 'email': email})
        return False
    except Exception as e:
        logger.error(f"{trans('agents_update_error', default='Error updating agent status for ID')} {agent_id}, email: {email}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': email})
        raise RuntimeError(f"Error updating agent: {str(e)}")

def delete_agent(db, agent_id: str, email: str) -> bool:
    """
    Delete an agent from the agents collection.

    Args:
        db: MongoDB database instance
        agent_id: ID of the agent to delete
        email: Email address of the agent

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If database deletion fails

    Example:
        deleted = delete_agent(db, agent_id='AG123456', email='agent@example.com')
    """
    try:
        result = db.agents.delete_one({'_id': agent_id.upper(), 'email': email.lower()})
        if result.deleted_count > 0:
            logger.info(f"{trans('general_agent_deleted', default='Deleted agent with ID')}: {agent_id}", 
                   extra={'user_id': 'no-user-id', 'email': email})
            return True
        logger.info(f"{trans('general_agent_not_found', default='Agent not found with ID')}: {agent_id}", 
                   extra={'user_id': 'no-user-id', 'email': email})
        return False
    except Exception as e:
        logger.error(f"{trans('general_agent_delete_error', default='Error deleting agent with ID')} {agent_id}: {str(e)}", 
                   exc_info=True, extra={'user_id': 'no-user-id', 'email': email})
        raise RuntimeError(f"Error deleting agent: {str(e)}")

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
        logger.error(f"{trans('general_budgets_fetch_error', default='Error retrieving budgets')}: {str(e)}", 
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
        logger.info(f"{trans('general_budget_created', default='Created budget with ID')}: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_budgets.cache_clear()
        return str(result.inserted_id)
    except BudgetData.validation_error as e:
        logger.error(f"Invalid budget data: {str(e)}", 
                   extra={'user_id': budget_data.get('user_id', 'no-user-id'), 'email': budget_data.get('email', 'no-email')})
        raise ValueError(f"Invalid budget data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_budget_creation_error', default='Error creating budget')}: {str(e)}", 
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
            logger.info(f"{trans('general_budget_updated', default='Updated budget with ID')}: {budget_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_budgets.cache_clear()
            return True
        logger.info(f"No changes made to budget with ID: {budget_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except BudgetData.validation_error() as e:
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
            logger.info(f"{trans('general_budget_deleted', default='Deleted budget with ID')}: {budget_id}", 
                   extra={'user_id': user_id, 'email': email})
            get_budgets.cache_clear()
            return True
        logger.info(f"{trans('general_budget_not_found', default='Budget not found with ID')}: {budget_id}", 
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
        logger.error(f"{trans('general_bills_fetch_error', default='Error retrieving bills')}: {str(e)}", 
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
        logger.info(f"{trans('general_bill_created', '')}: {result.inserted_id}", 
                    extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_bills.cache_clear()
        return str(result.inserted_id)
    except BillData.validation_error as e:
        logger.error(f"Invalid bill data: {str(e)}", 
                   extra={'user_id': bill_data.get('user_id', 'no-user-id'), 'email': bill_data.get('email', '')})
        raise ValueError(f"Invalid bill data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_bill_creation_error', default='Error creating bill')}: {str(e)}", 
                   exc_info=True, extra={'user_id': bill_data.get('user_id', 'no-user-id'), 'email': bill_data.get('email', '')})
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
            logger.info(f"{trans('general_bill_updated', default='Updated bill with ID')}: {bill_id}", 
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
            logger.info(f"{trans('general_bill_deleted', default='Deleted bill with ID')}: {bill_id}", 
                   extra={'user_id': user_id, 'email': email})
            get_bills.cache_clear()
            return True
        logger.info(f"{trans('general_bill_not_found', default='Bill not found with ID')}: {bill_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error deleting bill with ID {bill_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting bill: {str(e)}")

def create_bill_reminder(db, reminder_data: dict) -> str:
    """
    Create a new bill reminder in the bill_reminders collection.

    Args:
        db: MongoDB database instance
        reminder_data: Dictionary containing bill reminder information

    Returns:
        str: ID of the created bill reminder

    Raises:
        ValueError: If required fields are missing
        RuntimeError: For other database errors
    """
    try:
        required_fields = ['user_id', 'email', 'notification_id', 'type', 'message', 'sent_at']
        if not all(field in reminder_data for field in required_fields):
            raise ValueError(trans('general_missing_bill_reminder_fields', 'Missing required bill reminder fields'))
        reminder_data['email'] = reminder_data['email'].lower()
        result = db.bill_reminders.insert_one(reminder_data)
        logger.info(f"{trans('general_bill_reminder_created', default='Created bill reminder with ID')}: {result.inserted_id}", 
                   extra={'user_id': reminder_data.get('user_id', 'no-user-id'), 'email': reminder_data.get('email', 'no-email')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_bill_reminder_creation_error', default='Error creating bill reminder')}: {str(e)}", 
                    exc_info=True, extra={'user_id': reminder_data.get('user_id', 'no-user-id'), 'email': reminder_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating bill reminder: {str(e)}")

@lru_cache(maxsize=128)
def get_bill_reminders(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve bill reminder records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return

    Returns:
        list: List of bill reminder records

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com'}
        reminders = get_bill_reminders(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.bill_reminders.find(filter_kwargs).sort('sent_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_bill_reminders_fetch_error', default='Error retrieving bill reminders')}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving bill reminders: {str(e)}")

@lru_cache(maxsize=128)
def get_records(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve record entries based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of record entries

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com', 'type': 'debtor'}
        records = get_records(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.records.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_records_fetch_error', default='Error retrieving records')}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving records: {str(e)}")

def create_record(db, record_data: dict) -> str:
    """
    Create a new record in the records collection.

    Args:
        db: MongoDB database instance
        record_data: Dictionary containing record information

    Returns:
        str: ID of the created record

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors

    Example:
        record_data = {
            'user_id': 'user123',
            'email': 'user@example.com',
            'type': 'debtor',
            'name': 'John Doe',
            'amount_owed': 100.0,
            'description': 'Loan repayment'
        }
        record_id = create_record(db, record_data)
    """
    try:
        validated_data = RecordData(**record_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        result = db.records.insert_one(validated_data)
        logger.info(f"{trans('general_record_created', default='Created record with ID')}: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_records.cache_clear()
        return str(result.inserted_id)
    except RecordData.validation_error as e:
        logger.error(f"Invalid record data: {str(e)}", 
                   extra={'user_id': record_data.get('user_id', 'no-user-id'), 'email': record_data.get('email', 'no-email')})
        raise ValueError(f"Invalid record data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_record_creation_error', default='Error creating record')}: {str(e)}", 
                    exc_info=True, extra={'user_id': record_data.get('user_id', 'no-user-id'), 'email': record_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating record: {str(e)}")

def update_record(db, record_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a record in the records collection.

    Args:
        db: MongoDB database instance
        record_id: ID of the record to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails

    Example:
        update_data = {'amount_owed': 150.0, 'description': 'Updated loan repayment'}
        updated = update_record(db, record_id='1234567890', user_id='user123', email='user@example.com', update_data=update_data)
    """
    try:
        validated_data = RecordData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.records.update_one(
            {'_id': ObjectId(record_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_record_updated', default='Updated record with ID')}: {record_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_records.cache_clear()
            return True
        logger.info(f"No changes made to record with ID: {record_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except RecordData.validation_error as e:
        logger.error(f"Invalid update data for record: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid record update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating record with ID {record_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating record: {str(e)}")

def delete_record(db, record_id: str, user_id: str, email: str) -> bool:
    """
    Delete a record from the records collection.

    Args:
        db: MongoDB database instance
        record_id: ID of the record to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails

    Example:
        deleted = delete_record(db, record_id='1234567890', user_id='user123', email='user@example.com')
    """
    try:
        result = db.records.delete_one(
            {'_id': ObjectId(record_id), 'user_id': user_id, 'email': email.lower()}
        )
        if result.deleted_count > 0:
            logger.info(f"{trans('general_record_deleted', default='Deleted record with ID')}: {record_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_records.cache_clear()
            return True
        logger.info(f"{trans('general_record_not_found', default='Record not found with ID')}: {record_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error deleting record with ID {record_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting record: {str(e)}")

@lru_cache(maxsize=128)
def get_cashflows(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve cashflow records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of cashflow records

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com', 'type': 'receipt'}
        cashflows = get_cashflows(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.cashflows.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_cashflows_fetch_error', default='Error retrieving cashflows')}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving cashflows: {str(e)}")

def create_cashflow(db, cashflow_data: dict) -> str:
    """
    Create a new cashflow record in the cashflows collection.

    Args:
        db: MongoDB database instance
        cashflow_data: Dictionary containing cashflow information

    Returns:
        str: ID of the created cashflow record

    Raises:
        ValueError: If validation fails
        RuntimeError: For other database errors

    Example:
        cashflow_data = {
            'user_id': 'user123',
            'email': 'user@example.com',
            'type': 'receipt',
            'party_name': 'Client A',
            'amount': 500.0,
            'method': 'bank'
        }
        cashflow_id = create_cashflow(db, cashflow_data)
    """
    try:
        validated_data = CashflowData(**cashflow_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        result = db.cashflows.insert_one(validated_data)
        logger.info(f"{trans('general_cashflow_created', default='Created cashflow with ID')}: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_cashflows.cache_clear()
        return str(result.inserted_id)
    except CashflowData.validation_error as e:
        logger.error(f"Invalid cashflow data: {str(e)}", 
                   extra={'user_id': cashflow_data.get('user_id', 'no-user-id'), 'email': cashflow_data.get('email', 'no-email')})
        raise ValueError(f"Invalid cashflow data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_cashflow_creation_error', default='Error creating cashflow')}: {str(e)}", 
                    exc_info=True, extra={'user_id': cashflow_data.get('user_id', 'no-user-id'), 'email': cashflow_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating cashflow: {str(e)}")

def update_cashflow(db, cashflow_id: str, user_id: str, email: str, update_data: dict) -> bool:
    """
    Update a cashflow record in the cashflows collection.

    Args:
        db: MongoDB database instance
        cashflow_id: ID of the cashflow to update
        user_id: ID of the user
        email: Email address of the user
        update_data: Dictionary containing fields to update

    Returns:
        bool: True if updated, False if not found or no changes made

    Raises:
        ValueError: If validation fails
        RuntimeError: If update fails

    Example:
        update_data = {'amount': 600.0, 'method': 'cash'}
        updated = update_cashflow(db, cashflow_id='1234567890', user_id='user123', email='user@example.com', update_data=update_data)
    """
    try:
        validated_data = CashflowData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.cashflows.update_one(
            {'_id': ObjectId(cashflow_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_cashflow_updated', default='Updated cashflow with ID')}: {cashflow_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_cashflows.cache_clear()
            return True
        logger.info(f"No changes made to cashflow with ID: {cashflow_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except CashflowData.validation_error as e:
        logger.error(f"Invalid update data for cashflow: {str(e)}", 
                   extra={'user_id': user_id, 'email': email})
        raise ValueError(f"Invalid cashflow update data: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating cashflow with ID {cashflow_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error updating cashflow: {str(e)}")

def delete_cashflow(db, cashflow_id: str, user_id: str, email: str) -> bool:
    """
    Delete a cashflow record from the cashflows collection.

    Args:
        db: MongoDB database instance
        cashflow_id: ID of the cashflow to delete
        user_id: ID of the user
        email: Email address of the user

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails

    Example:
        deleted = delete_cashflow(db, cashflow_id='1234567890', user_id='user123', email='user@example.com')
    """
    try:
        result = db.cashflows.delete_one(
            {'_id': ObjectId(cashflow_id), 'user_id': user_id, 'email': email.lower()}
        )
        if result.deleted_count > 0:
            logger.info(f"{trans('general_cashflow_deleted', default='Deleted cashflow with ID')}: {cashflow_id}", 
                       extra={'user_id': user_id, 'email': email})
            get_cashflows.cache_clear()
            return True
        logger.info(f"{trans('general_cashflow_not_found', default='Cashflow not found with ID')}: {cashflow_id}", 
                   extra={'user_id': user_id, 'email': email})
        return False
    except Exception as e:
        logger.error(f"Error deleting cashflow with ID {cashflow_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting cashflow: {str(e)}")

def create_ficore_credit_transaction(db, user_id: str, email: str, amount: int, transaction_type: str, ref: Optional[str]=None, 
                                    facilitated_by_agent: Optional[str]=None, payment_method: Optional[str]=None, 
                                    cash_amount: Optional[float]=None, notes: Optional[str]=None) -> str:
    """
    Create a new fiscal credit transaction with atomic updates to user balance.

    Args:
        db: MongoDB database instance
        user_id: ID of the user
        email: Email address of the user
        amount: Amount of fiscal credits
        transaction_type: Type of transaction (add, spend, purchase, admin_credit, create_shopping_list)
        ref: Reference ID (optional)
        facilitated_by_agent: Agent ID facilitating the transaction (optional)
        payment_method: Payment method used (optional)
        cash_amount: Cash amount involved (optional)
        notes: Additional notes (optional)

    Returns:
        str: ID of the created transaction

    Raises:
        ValueError: If validation fails or insufficient balance
        RuntimeError: For other database errors

    Example:
        transaction_id = create_ficore_credit_transaction(
            db, user_id='user123', email='user@example.com', amount=100, 
            transaction_type='add', payment_method='card'
        )
    """
    try:
        if transaction_type not in ['add', 'spend', 'purchase', 'admin_credit', 'create_shopping_list']:
            raise ValueError(f"Invalid transaction type: {transaction_type}")
        
        with db.client.start_session() as session:
            with session.start_transaction():
                # Check user balance for spend or create_shopping_list
                if transaction_type in ['spend', 'create_shopping_list']:
                    user = db.users.find_one({'_id': user_id, 'email': email.lower()}, session=session)
                    if not user:
                        raise ValueError(f"User not found: {user_id}, {email}")
                    if user.get('ficore_credit_balance', 0) < amount:
                        raise ValueError(f"Insufficient fiscal credit balance for user {user_id}")
                
                # Update user balance
                balance_update = {'$inc': {'ficore_credit_balance': amount if transaction_type in ['add', 'purchase', 'admin_credit'] else -amount}}
                result = db.users.update_one(
                    {'_id': user_id, 'email': email.lower()},
                    balance_update,
                    session=session
                )
                if result.modified_count == 0:
                    raise ValueError(f"Failed to update user balance for {user_id}")
                
                # Create transaction record
                transaction_data = {
                    'user_id': user_id,
                    'email': email.lower(),
                    'amount': amount,
                    'type': transaction_type,
                    'ref': ref,
                    'date': datetime.utcnow(),
                    'facilitated_by_agent': facilitated_by_agent,
                    'payment_method': payment_method,
                    'cash_amount': cash_amount,
                    'notes': sanitize_input(notes) if notes else None
                }
                result = db.ficore_credit_transactions.insert_one(transaction_data, session=session)
                logger.info(f"{trans('credits_transaction_created', default='Created fiscal credit transaction with ID')}: {result.inserted_id}", 
                           extra={'user_id': user_id, 'email': email})
                get_ficore_credit_transactions.cache_clear()
                get_user.cache_clear()
                get_user_by_email.cache_clear()
                return str(result.inserted_id)
    except ValueError as e:
        logger.error(f"Validation error in fiscal credit transaction: {str(e)}", 
                   extra={'user_id': user_id, 'email': email}, exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Error creating fiscal credit transaction for user {user_id}, email: {email}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error creating fiscal credit transaction: {str(e)}")

@lru_cache(maxsize=128)
def get_ficore_credit_transactions(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve fiscal credit transaction records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of fiscal credit transaction records

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com'}
        transactions = get_ficore_credit_transactions(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.ficore_credit_transactions.find(filter_kwargs).sort('date', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('credits_transactions_fetch_error', default='Error retrieving fiscal credit transactions')}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving fiscal credit transactions: {str(e)}")

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

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com'}
        shopping_lists = get_shopping_lists(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.shopping_lists.find(filter_kwargs).sort('updated_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_shopping_lists_fetch_error', default='Error retrieving shopping lists')}: {str(e)}", 
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

    Example:
        shopping_list_data = {
            'user_id': 'user123',
            'email': 'user@example.com',
            'name': 'Grocery List',
            'budget': 100.0,
            'status': 'active'
        }
        list_id = create_shopping_list(db, shopping_list_data)
    """
    try:
        validated_data = ShoppingListData(**shopping_list_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        result = db.shopping_lists.insert_one(validated_data)
        logger.info(f"{trans('general_shopping_list_created', default='Created shopping list with ID')}: {result.inserted_id}", 
                   extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
        get_shopping_lists.cache_clear()
        return str(result.inserted_id)
    except ShoppingListData.validation_error as e:
        logger.error(f"Invalid shopping list data: {str(e)}", 
                   extra={'user_id': shopping_list_data.get('user_id', 'no-user-id'), 'email': shopping_list_data.get('email', 'no-email')})
        raise ValueError(f"Invalid shopping list data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_shopping_list_creation_error', default='Error creating shopping list')}: {str(e)}", 
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

    Example:
        added = add_collaborator_to_shopping_list(db, list_id='1234567890', user_id='user123', email='user@example.com', collaborator_email='collab@example.com')
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

    Example:
        removed = remove_collaborator_from_shopping_list(db, list_id='1234567890', user_id='user123', email='user@example.com', collaborator_email='collab@example.com')
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

    Example:
        update_data = {'name': 'Updated Grocery List', 'budget': 150.0}
        updated = update_shopping_list(db, list_id='1234567890', user_id='user123', email='user@example.com', update_data=update_data)
    """
    try:
        validated_data = ShoppingListData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        result = db.shopping_lists.update_one(
            {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
            {'$set': validated_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_shopping_list_updated', default='Updated shopping list with ID')}: {list_id}", 
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

    Example:
        deleted = delete_shopping_list(db, list_id='1234567890', user_id='user123', email='user@example.com')
    """
    try:
        with db.client.start_session() as session:
            with session.start_transaction():
                # Delete associated shopping items
                db.shopping_items.delete_many({'list_id': list_id, 'user_id': user_id, 'email': email.lower()}, session=session)
                # Delete the shopping list
                result = db.shopping_lists.delete_one(
                    {'_id': ObjectId(list_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if result.deleted_count > 0:
                    logger.info(f"{trans('general_shopping_list_deleted', default='Deleted shopping list with ID')}: {list_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_shopping_lists.cache_clear()
                    get_shopping_items.cache_clear()
                    return True
                logger.info(f"{trans('general_shopping_list_not_found', default='Shopping list not found with ID')}: {list_id}", 
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

    Example:
        filter_kwargs = {'user_id': 'user123', 'email': 'user@example.com', 'list_id': '1234567890'}
        items = get_shopping_items(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.shopping_items.find(filter_kwargs).sort('created_at', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_shopping_items_fetch_error', default='Error retrieving shopping items')}: {str(e)}", 
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

    Example:
        shopping_item_data = {
            'user_id': 'user123',
            'email': 'user@example.com',
            'list_id': '1234567890',
            'name': 'Apples',
            'quantity': 5,
            'price': 2.5,
            'category': 'fruits',
            'status': 'to_buy'
        }
        item_id = create_shopping_item(db, shopping_item_data)
    """
    try:
        validated_data = ShoppingItemData(**shopping_item_data).dict(exclude_unset=True)
        validated_data['created_at'] = validated_data.get('created_at', datetime.utcnow())
        validated_data['updated_at'] = validated_data.get('updated_at', datetime.utcnow())
        
        with db.client.start_session() as session:
            with session.start_transaction():
                result = db.shopping_items.insert_one(validated_data, session=session)
                # Update total_spent if item is bought
                if validated_data['status'] == 'bought':
                    db.shopping_lists.update_one(
                        {'_id': ObjectId(validated_data['list_id']), 'user_id': validated_data['user_id'], 'email': validated_data['email'].lower()},
                        {'$inc': {'total_spent': validated_data['price'] * validated_data['quantity']}, '$set': {'updated_at': datetime.utcnow()}},
                        session=session
                    )
                logger.info(f"{trans('general_shopping_item_created', default='Created shopping item with ID')}: {result.inserted_id}", 
                           extra={'user_id': validated_data.get('user_id', 'no-user-id'), 'email': validated_data.get('email', 'no-email')})
                get_shopping_items.cache_clear()
                get_shopping_lists.cache_clear()
                return str(result.inserted_id)
    except ShoppingItemData.validation_error as e:
        logger.error(f"Invalid shopping item data: {str(e)}", 
                   extra={'user_id': shopping_item_data.get('user_id', 'no-user-id'), 'email': shopping_item_data.get('email', 'no-email')})
        raise ValueError(f"Invalid shopping item data: {str(e)}")
    except Exception as e:
        logger.error(f"{trans('general_shopping_item_creation_error', default='Error creating shopping item')}: {str(e)}", 
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

    Example:
        update_data = {'quantity': 10, 'price': 3.0, 'status': 'bought'}
        updated = update_shopping_item(db, item_id='1234567890', user_id='user123', email='user@example.com', update_data=update_data)
    """
    try:
        validated_data = ShoppingItemData(**{**update_data, 'user_id': user_id, 'email': email}).dict(exclude_unset=True)
        validated_data['updated_at'] = datetime.utcnow()
        
        with db.client.start_session() as session:
            with session.start_transaction():
                # Get current item data
                current_item = db.shopping_items.find_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if not current_item:
                    logger.info(f"Shopping item not found with ID: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    return False
                
                # Update item
                result = db.shopping_items.update_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    {'$set': validated_data},
                    session=session
                )
                
                if result.modified_count > 0:
                    # Recalculate total_spent
                    old_amount = current_item['price'] * current_item['quantity'] if current_item['status'] == 'bought' else 0
                    new_amount = validated_data['price'] * validated_data['quantity'] if validated_data['status'] == 'bought' else 0
                    amount_diff = new_amount - old_amount
                    
                    if amount_diff != 0:
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(validated_data['list_id']), 'user_id': user_id, 'email': email.lower()},
                            {'$inc': {'total_spent': amount_diff}, '$set': {'updated_at': datetime.utcnow()}},
                            session=session
                        )
                    
                    logger.info(f"{trans('general_shopping_item_updated', default='Updated shopping item with ID')}: {item_id}", 
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

    Example:
        deleted = delete_shopping_item(db, item_id='1234567890', user_id='user123', email='user@example.com')
    """
    try:
        with db.client.start_session() as session:
            with session.start_transaction():
                # Get current item data
                item = db.shopping_items.find_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                if not item:
                    logger.info(f"{trans('general_shopping_item_not_found', default='Shopping item not found with ID')}: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    return False
                
                # Delete item
                result = db.shopping_items.delete_one(
                    {'_id': ObjectId(item_id), 'user_id': user_id, 'email': email.lower()},
                    session=session
                )
                
                if result.deleted_count > 0:
                    # Update total_spent if item was bought
                    if item['status'] == 'bought':
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(item['list_id']), 'user_id': user_id, 'email': email.lower()},
                            {'$inc': {'total_spent': -(item['price'] * item['quantity'])}, '$set': {'updated_at': datetime.utcnow()}},
                            session=session
                        )
                    logger.info(f"{trans('general_shopping_item_deleted', default='Deleted shopping item with ID')}: {item_id}", 
                               extra={'user_id': user_id, 'email': email})
                    get_shopping_items.cache_clear()
                    get_shopping_lists.cache_clear()
                    return True
                return False
    except Exception as e:
        logger.error(f"Error deleting shopping item with ID {item_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': user_id, 'email': email})
        raise RuntimeError(f"Error deleting shopping item: {str(e)}")

@lru_cache(maxsize=128)
def get_audit_logs(db, filter_kwargs: dict, skip: int=0, limit: int=10) -> List[dict]:
    """
    Retrieve audit log records based on filter criteria with pagination.

    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        list: List of audit log records

    Raises:
        RuntimeError: If database query fails

    Example:
        filter_kwargs = {'admin_id': 'admin123', 'email': 'admin@example.com'}
        logs = get_audit_logs(db, filter_kwargs=filter_kwargs, skip=0, limit=10)
    """
    try:
        if 'email' in filter_kwargs:
            filter_kwargs['email'] = filter_kwargs['email'].lower()
        return list(db.audit_logs.find(filter_kwargs).sort('timestamp', DESCENDING).skip(skip).limit(limit))
    except Exception as e:
        logger.error(f"{trans('general_audit_logs_fetch_error', default='Error retrieving audit logs')}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving audit logs: {str(e)}")

def create_audit_log(db, audit_data: dict) -> str:
    """
    Create a new audit log entry in the audit_logs collection.

    Args:
        db: MongoDB database instance
        audit_data: Dictionary containing audit log information

    Returns:
        str: ID of the created audit log

    Raises:
        ValueError: If required fields are missing
        RuntimeError: For other database errors

    Example:
        audit_data = {
            'admin_id': 'admin123',
            'email': 'admin@example.com',
            'action': 'user_updated',
            'details': {'user_id': 'user123'},
            'timestamp': datetime.utcnow()
        }
        log_id = create_audit_log(db, audit_data)
    """
    try:
        required_fields = ['admin_id', 'email', 'action', 'timestamp']
        if not all(field in audit_data for field in required_fields):
            raise ValueError(trans('general_missing_audit_fields', default='Missing required audit log fields'))
        audit_data['email'] = audit_data['email'].lower()
        result = db.audit_logs.insert_one(audit_data)
        logger.info(f"{trans('general_audit_log_created', default='Created audit log with ID')}: {result.inserted_id}", 
                   extra={'user_id': audit_data.get('admin_id', 'no-user-id'), 'email': audit_data.get('email', 'no-email')})
        get_audit_logs.cache_clear()
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_audit_log_creation_error', default='Error creating audit log')}: {str(e)}", 
                    exc_info=True, extra={'user_id': audit_data.get('admin_id', 'no-user-id'), 'email': audit_data.get('email', 'no-email')})
        raise RuntimeError(f"Error creating audit log: {str(e)}")

def get_config(db, config_id: str) -> Optional[dict]:
    """
    Retrieve a system configuration value by ID.

    Args:
        db: MongoDB database instance
        config_id: ID of the configuration to retrieve

    Returns:
        dict: Configuration document or None if not found

    Raises:
        RuntimeError: If database query fails

    Example:
        config = get_config(db, config_id='default_language')
    """
    try:
        config = db.system_config.find_one({'_id': config_id})
        if config:
            logger.info(f"Retrieved config {config_id}", 
                       extra={'user_id': 'no-user-id', 'email': 'no-email'})
            return config
        logger.info(f"Config {config_id} not found", 
                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
        return None
    except Exception as e:
        logger.error(f"Error retrieving config {config_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error retrieving config: {str(e)}")

def set_config(db, config_id: str, value: Union[bool, int, float, str, dict, list]) -> bool:
    """
    Set or update a system configuration value.

    Args:
        db: MongoDB database instance
        config_id: ID of the configuration to set
        value: Configuration value to set

    Returns:
        bool: True if set/updated, False if no changes made

    Raises:
        RuntimeError: If update fails

    Example:
        updated = set_config(db, config_id='default_language', value='en')
    """
    try:
        result = db.system_config.update_one(
            {'_id': config_id},
            {'$set': {'value': value}},
            upsert=True
        )
        if result.modified_count > 0 or result.upserted_id:
            logger.info(f"Set/updated config {config_id}", 
                       extra={'user_id': 'no-user-id', 'email': 'no-email'})
            return True
        logger.info(f"No changes made to config {config_id}", 
                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
        return False
    except Exception as e:
        logger.error(f"Error setting config {config_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error setting config: {str(e)}")

def delete_config(db, config_id: str) -> bool:
    """
    Delete a system configuration value.

    Args:
        db: MongoDB database instance
        config_id: ID of the configuration to delete

    Returns:
        bool: True if deleted, False if not found

    Raises:
        RuntimeError: If deletion fails

    Example:
        deleted = delete_config(db, config_id='default_language')
    """
    try:
        result = db.system_config.delete_one({'_id': config_id})
        if result.deleted_count > 0:
            logger.info(f"Deleted config {config_id}", 
                       extra={'user_id': 'no-user-id', 'email': 'no-email'})
            return True
        logger.info(f"Config {config_id} not found", 
                   extra={'user_id': 'no-user-id', 'email': 'no-email'})
        return False
    except Exception as e:
        logger.error(f"Error deleting config {config_id}: {str(e)}", 
                    exc_info=True, extra={'user_id': 'no-user-id', 'email': 'no-email'})
        raise RuntimeError(f"Error deleting config: {str(e)}")
