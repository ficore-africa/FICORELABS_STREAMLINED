from datetime import datetime
from pymongo import ASCENDING
from pymongo.errors import OperationFailure
import logging
from translations import trans
from bson import ObjectId

# Configure logger for the tax models module
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define tax-related collection schemas
tax_collection_schemas = {
    'tax_rates': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['role', 'min_income', 'max_income', 'rate', 'description'],
                'properties': {
                    'role': {'enum': ['personal', 'trader', 'agent', 'company']},
                    'min_income': {'bsonType': 'number'},
                    'max_income': {'bsonType': 'number'},
                    'rate': {'bsonType': 'number', 'minimum': 0, 'maximum': 1},
                    'description': {'bsonType': 'string'},
                    'session_id': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('role', ASCENDING)]},
            {'key': [('min_income', ASCENDING)]},
            {'key': [('session_id', ASCENDING)]}
        ]
    },
    'vat_rules': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['category', 'rate', 'description'],
                'properties': {
                    'category': {'bsonType': 'string'},
                    'rate': {'bsonType': 'number', 'minimum': 0, 'maximum': 1},
                    'description': {'bsonType': 'string'},
                    'session_id': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('category', ASCENDING)]},
            {'key': [('session_id', ASCENDING)]}
        ]
    },
    'tax_version': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['_id', 'version', 'updated_at'],
                'properties': {
                    '_id': {'bsonType': 'string'},
                    'version': {'bsonType': 'string'},
                    'updated_at': {'bsonType': 'date'}
                }
            }
        },
        'indexes': [
            {'key': [('version', ASCENDING)]}
        ]
    },
    'tax_reminders': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['user_id', 'reminder_date', 'tax_type', 'description'],
                'properties': {
                    'user_id': {'bsonType': 'string'},
                    'reminder_date': {'bsonType': 'date'},
                    'tax_type': {'bsonType': 'string'},
                    'description': {'bsonType': 'string'},
                    'session_id': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('user_id', ASCENDING)]},
            {'key': [('reminder_date', ASCENDING)]},
            {'key': [('session_id', ASCENDING)]}
        ]
    },
    'tax_deadlines': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['tax_type', 'deadline_date', 'description'],
                'properties': {
                    'tax_type': {'bsonType': 'string'},
                    'deadline_date': {'bsonType': 'date'},
                    'description': {'bsonType': 'string'},
                    'session_id': {'bsonType': ['string', 'null']}
                }
            }
        },
        'indexes': [
            {'key': [('tax_type', ASCENDING)]},
            {'key': [('deadline_date', ASCENDING)]},
            {'key': [('session_id', ASCENDING)]}
        ]
    },
    'payment_locations': {
        'validator': {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['name', 'address', 'contact'],
                'properties': {
                    'name': {'bsonType': 'string'},
                    'address': {'bsonType': 'string'},
                    'contact': {'bsonType': 'string'},
                    'coordinates': {
                        'bsonType': ['object', 'null'],
                        'properties': {
                            'lat': {'bsonType': 'number'},
                            'lng': {'bsonType': 'number'}
                        }
                    }
                }
            }
        },
        'indexes': [
            {'key': [('name', ASCENDING)]}
        ]
    }
}

def initialize_tax_data(db, trans):
    """
    Initialize tax-related collections and seed initial data.
    """
    collections = db.list_collection_names()

    # Create or update tax-related collections
    for collection_name, config in tax_collection_schemas.items():
        try:
            if collection_name not in collections:
                db.create_collection(collection_name, validator=config.get('validator', {}))
                logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}", 
                            extra={'session_id': 'no-session-id'})
            else:
                db.command('collMod', collection_name, validator=config.get('validator', {}))
                logger.info(f"Updated validator for collection: {collection_name}", 
                            extra={'session_id': 'no-session-id'})
            
            # Create indexes
            for index in config.get('indexes', []):
                db[collection_name].create_index(index['key'])
                logger.info(f"Created index for {collection_name}: {index['key']}", 
                            extra={'session_id': 'no-session-id'})
        except Exception as e:
            logger.error(f"Failed to initialize collection {collection_name}: {str(e)}", 
                        exc_info=True, extra={'session_id': 'no-session-id'})
            raise

    # Seed tax_version
    try:
        tax_version_collection = db.tax_version
        if tax_version_collection.count_documents({}) == 0:
            current_tax_version = '2025-07-02'
            tax_version_collection.insert_one({
                '_id': 'version',
                'version': current_tax_version,
                'updated_at': datetime.utcnow()
            })
            logger.info(f"{trans('general_tax_version_initialized', default='Initialized tax version in MongoDB')}: {current_tax_version}", 
                        extra={'session_id': 'no-session-id'})
    except Exception as e:
        logger.error(f"Failed to seed tax version: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

    # Seed vat_rules
    try:
        vat_rules_collection = db.vat_rules
        if vat_rules_collection.count_documents({}) == 0:
            vat_rules_collection.insert_many([
                {
                    'category': 'standard',
                    'rate': 0.20,
                    'description': 'Standard VAT rate for most goods and services',
                    'session_id': None
                },
                {
                    'category': 'reduced',
                    'rate': 0.05,
                    'description': 'Reduced VAT rate for specific goods',
                    'session_id': None
                }
            ])
            logger.info(f"{trans('general_vat_rules_initialized', default='Initialized VAT rules in MongoDB')}", 
                        extra={'session_id': 'no-session-id'})
    except Exception as e:
        logger.error(f"Failed to seed vat_rules: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_rates(db, filter_kwargs):
    """
    Retrieve tax rate records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax rate records
    """
    try:
        return list(db.tax_rates.find(filter_kwargs).sort('min_income', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('tax_rates_fetch_error', default='Error getting tax rates')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_vat_rules(db, filter_kwargs):
    """
    Retrieve VAT rule records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of VAT rule records
    """
    try:
        return list(db.vat_rules.find(filter_kwargs).sort('category', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('vat_rules_fetch_error', default='Error getting VAT rules')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_reminders(db, filter_kwargs):
    """
    Retrieve tax reminder records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax reminder records
    """
    try:
        return list(db.tax_reminders.find(filter_kwargs).sort('reminder_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('tax_reminders_fetch_error', default='Error getting tax reminders')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_tax_deadlines(db, filter_kwargs):
    """
    Retrieve tax deadline records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of tax deadline records
    """
    try:
        return list(db.tax_deadlines.find(filter_kwargs).sort('deadline_date', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('tax_deadlines_fetch_error', default='Error getting tax deadlines')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_payment_locations(db, filter_kwargs):
    """
    Retrieve payment location records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of payment location records
    """
    try:
        return list(db.payment_locations.find(filter_kwargs).sort('name', ASCENDING))
    except Exception as e:
        logger.error(f"{trans('general_payment_locations_fetch_error', default='Error getting payment locations')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_payment_location(db, location_data):
    """
    Create a new payment location in the payment_locations collection.
    
    Args:
        db: MongoDB database instance
        location_data: Dictionary containing payment location information
    
    Returns:
        str: ID of the created payment location
    """
    try:
        required_fields = ['name', 'address', 'contact']
        if not all(field in location_data for field in required_fields):
            raise ValueError(trans('general_missing_location_fields', default='Missing required payment location fields'))
        result = db.payment_locations.insert_one(location_data)
        logger.info(f"{trans('general_payment_location_created', default='Created payment location with ID')}: {result.inserted_id}", 
                   extra={'session_id': 'no-session-id'})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_payment_location_creation_error', default='Error creating payment location')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_payment_location(db, location_id, update_data):
    """
    Update a payment location in the payment_locations collection.
    
    Args:
        db: MongoDB database instance
        location_id: The ID of the payment location to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.payment_locations.update_one(
            {'_id': ObjectId(location_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_payment_location_updated', default='Updated payment location with ID')}: {location_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_payment_location_no_change', default='No changes made to payment location with ID')}: {location_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_payment_location_update_error', default='Error updating payment location with ID')} {location_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_vat_rule(db, vat_rule_data):
    """
    Create a new VAT rule in the vat_rules collection.
    
    Args:
        db: MongoDB database instance
        vat_rule_data: Dictionary containing VAT rule information
    
    Returns:
        str: ID of the created VAT rule
    """
    try:
        required_fields = ['category', 'rate', 'description']
        if not all(field in vat_rule_data for field in required_fields):
            raise ValueError(trans('vat_missing_rule_fields', default='Missing required VAT rule fields'))
        result = db.vat_rules.insert_one(vat_rule_data)
        logger.info(f"{trans('vat_rule_created', default='Created VAT rule with ID')}: {result.inserted_id}", 
                   extra={'session_id': vat_rule_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('vat_rule_creation_error', default='Error creating VAT rule')}: {str(e)}", 
                    exc_info=True, extra={'session_id': vat_rule_data.get('session_id', 'no-session-id')})
        raise

def to_dict_tax_rate(record):
    """Convert tax rate record to dictionary."""
    if not record:
        return {'role': None, 'rate': None}
    return {
        'id': str(record.get('_id', '')),
        'role': record.get('role', ''),
        'min_income': record.get('min_income', 0),
        'max_income': record.get('max_income', 0),
        'rate': record.get('rate', 0.0),
        'description': record.get('description', ''),
        'session_id': record.get('session_id', None)
    }

def to_dict_vat_rule(record):
    """Convert VAT rule record to dictionary."""
    if not record:
        return {'category': None, 'rate': None}
    return {
        'id': str(record.get('_id', '')),
        'category': record.get('category', ''),
        'rate': record.get('rate', 0.0),
        'description': record.get('description', ''),
        'session_id': record.get('session_id', None)
    }

def to_dict_tax_reminder(record):
    """Convert tax reminder record to dictionary."""
    if not record:
        return {'tax_type': None, 'reminder_date': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'reminder_date': record.get('reminder_date'),
        'tax_type': record.get('tax_type', ''),
        'description': record.get('description', ''),
        'session_id': record.get('session_id', None)
    }

def to_dict_tax_deadline(record):
    """Convert tax deadline record to dictionary."""
    if not record:
        return {'tax_type': None, 'deadline_date': None}
    return {
        'id': str(record.get('_id', '')),
        'tax_type': record.get('tax_type', ''),
        'deadline_date': record.get('deadline_date'),
        'description': record.get('description', ''),
        'session_id': record.get('session_id', None)
    }

def to_dict_payment_location(record):
    """Convert payment location record to dictionary."""
    if not record:
        return {'name': None, 'address': None}
    return {
        'id': str(record.get('_id', '')),
        'name': record.get('name', ''),
        'address': record.get('address', ''),
        'contact': record.get('contact', ''),
        'coordinates': record.get('coordinates', {})
    }
