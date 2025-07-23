from pymongo import ASCENDING
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

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
                db[collection_name].create_index(**index)
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

    # Seed vat_rules (example data, adjust as needed)
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