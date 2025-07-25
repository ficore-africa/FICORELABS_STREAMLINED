import os
import sys
import logging
import re
import uuid
from datetime import datetime, date
from flask import (
    Flask, jsonify, request, render_template, redirect, url_for, flash,
    make_response, has_request_context, g, send_from_directory, current_app, abort, session
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from functools import wraps
from mailersend_email import init_email_config
from scheduler_setup import init_scheduler
from models import (
    create_user, get_user_by_email, get_user, initialize_app_data, update_user,
    to_dict_user
)
from tax_models import (
    initialize_tax_data, get_payment_locations, to_dict_payment_location
)
import utils
from translations import register_translation, trans, get_translations, get_all_translations, get_module_translations
from flask_login import LoginManager, login_required, current_user, UserMixin, logout_user
from flask_wtf.csrf import CSRFError
from jinja2.exceptions import TemplateNotFound
from pymongo import MongoClient
import certifi
from credits.routes import credits_bp
from flask_mailman import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from flask_compress import Compress
import requests
from business_finance import business

# Load environment variables
load_dotenv()

# Set up logging with enhanced user tracking
root_logger = logging.getLogger('ficore_app')
root_logger.setLevel(logging.INFO)

class UserFormatter(logging.Formatter):
    """Custom formatter to include user_id, email, role, and IP in logs."""
    def format(self, record):
        record.user_id = getattr(record, 'user_id', 'no-user-id')
        record.email = getattr(record, 'email', 'no-email')
        record.user_role = getattr(record, 'user_role', 'anonymous')
        record.ip_address = getattr(record, 'ip_address', 'unknown')
        return super().format(record)

class UserAdapter(logging.LoggerAdapter):
    """Adapter to inject user context into log messages."""
    def process(self, msg, kwargs):
        kwargs['extra'] = kwargs.get('extra', {})
        user_id = 'no-user-id'
        email = 'no-email'
        user_role = 'anonymous'
        ip_address = 'unknown'
        try:
            if has_request_context():
                if current_user.is_authenticated:
                    user_id = current_user.id
                    email = current_user.email
                    user_role = current_user.role
                ip_address = request.remote_addr
        except Exception as e:
            user_id = f'user-error-{str(uuid.uuid4())[:8]}'
            kwargs['extra']['user_error'] = str(e)
        kwargs['extra']['user_id'] = user_id
        kwargs['extra']['email'] = email
        kwargs['extra']['user_role'] = user_role
        kwargs['extra']['ip_address'] = ip_address
        return msg, kwargs

logger = UserAdapter(root_logger, {})

# Initialize extensions
login_manager = LoginManager()
csrf = CSRFProtect()
babel = Babel()
compress = Compress()
limiter = Limiter(key_func=get_remote_address, default_limits=['200 per day', '50 per hour'], storage_uri='memory://')

# Input validation utilities
def validate_user_id(user_id):
    """Validate user_id format (UUID)."""
    try:
        uuid_obj = uuid.UUID(str(user_id))
        return str(uuid_obj) == str(user_id)
    except ValueError:
        return False

def validate_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

# Decorators
def admin_required(f):
    """Decorator to restrict access to admin users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            logger.warning("Unauthorized access attempt to admin route")
            return redirect(url_for('users.login'))
        if not current_user.is_admin:
            flash(trans('general_no_permission', default='You do not have permission to access this page.'), 'danger')
            logger.warning(f"Non-admin user {current_user.id}/{current_user.email} attempted access")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def validate_identity(f):
    """Decorator to validate user_id and email in requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = kwargs.get('user_id') or (current_user.id if current_user.is_authenticated else None)
        email = kwargs.get('email') or (current_user.email if current_user.is_authenticated else None)
        if user_id and not validate_user_id(user_id):
            logger.warning(f"Invalid user_id: {user_id}")
            return jsonify({'error': trans('invalid_user_id')}), 400
        if email and not validate_email(email):
            logger.warning(f"Invalid email: {email}")
            return jsonify({'error': trans('invalid_email')}), 400
        return f(*args, **kwargs)
    return decorated_function

def setup_logging(app):
    """Configure logging with StreamHandler for Flask, Werkzeug, and PyMongo."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    handler.setFormatter(UserFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [user: %(user_id)s, email: %(email)s, role: %(user_role)s, ip: %(ip_address)s]'))
    root_logger.handlers = []
    root_logger.addHandler(handler)
    
    flask_logger = logging.getLogger('flask')
    werkzeug_logger = logging.getLogger('werkzeug')
    pymongo_logger = logging.getLogger('pymongo')
    flask_logger.handlers = []
    werkzeug_logger.handlers = []
    pymongo_logger.handlers = []
    flask_logger.addHandler(handler)
    werkzeug_logger.addHandler(handler)
    pymongo_logger.addHandler(handler)
    flask_logger.setLevel(logging.INFO)
    werkzeug_logger.setLevel(logging.INFO)
    pymongo_logger.setLevel(logging.INFO)
    
    logger.info('Logging setup complete with StreamHandler')

def check_mongodb_connection(app):
    """Verify MongoDB connection with ping command."""
    try:
        client = app.extensions['mongo']
        client.admin.command('ping')
        logger.info('MongoDB connection verified')
        return True
    except Exception as e:
        logger.error(f'MongoDB connection failed: {str(e)}', exc_info=True)
        return False

class User(UserMixin):
    """User class for Flask-Login with dual identity (user_id, email)."""
    def __init__(self, id, email, display_name=None, role='personal', is_admin=False, setup_complete=False, coin_balance=0, ficore_credit_balance=0, language='en', dark_mode=False):
        if not validate_user_id(id):
            raise ValueError(f"Invalid user_id: {id}")
        if not validate_email(email):
            raise ValueError(f"Invalid email: {email}")
        self.id = id
        self.email = email.lower()
        self.display_name = display_name or id
        self.role = role
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.coin_balance = coin_balance
        self.ficore_credit_balance = ficore_credit_balance
        self.language = language
        self.dark_mode = dark_mode

    def get(self, key, default=None):
        """Retrieve user attribute from MongoDB."""
        try:
            with current_app.app_context():
                user = current_app.extensions['mongo']['ficodb'].users.find_one({'_id': self.id, 'email': self.email})
                if user and key == 'language':
                    self.language = user.get('language', 'en')
                return user.get(key, default) if user else default
        except Exception as e:
            logger.error(f'Error fetching user data for {self.id}/{self.email}: {str(e)}', exc_info=True)
            return default

    @property
    def is_active(self):
        """Check if user account is active."""
        try:
            with current_app.app_context():
                user = current_app.extensions['mongo']['ficodb'].users.find_one({'_id': self.id, 'email': self.email})
                return user.get('is_active', True) if user else False
        except Exception as e:
            logger.error(f'Error checking active status for user {self.id}/{self.email}: {str(e)}', exc_info=True)
            return False

    def get_id(self):
        """Return user_id as string for Flask-Login."""
        return str(self.id)

    def get_first_name(self):
        """Retrieve user's first name from personal details."""
        try:
            with current_app.app_context():
                user = current_app.extensions['mongo']['ficodb'].users.find_one({'_id': self.id, 'email': self.email})
                if user and 'personal_details' in user:
                    return user['personal_details'].get('first_name', self.display_name)
                return self.display_name
        except Exception as e:
            logger.error(f'Error fetching first name for user {self.id}/{self.email}: {str(e)}', exc_info=True)
            return self.display_name

def create_app():
    """Initialize and configure Flask application."""
    app = Flask(__name__, template_folder='templates', static_folder='static')
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Load configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        logger.error('SECRET_KEY environment variable is not set')
        raise ValueError('SECRET_KEY must be set')

    app.config['SERVER_NAME'] = os.getenv('SERVER_NAME', 'ficore-africa.onrender.com')
    app.config['APPLICATION_ROOT'] = os.getenv('APPLICATION_ROOT', '/')
    app.config['PREFERRED_URL_SCHEME'] = os.getenv('PREFERRED_URL_SCHEME', 'https')
    
    app.config['MONGO_URI'] = os.getenv('MONGO_URI')
    if not app.config['MONGO_URI']:
        logger.error('MONGO_URI environment variable is not set')
        raise ValueError('MONGO_URI must be set')
    
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
    app.config['GOOGLE_API_KEY'] = os.getenv('GOOGLE_API_KEY')
    app.config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', 587))
    app.config['SMTP_USERNAME'] = os.getenv('SMTP_USERNAME')
    app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD')
    app.config['SMS_API_URL'] = os.getenv('SMS_API_URL')
    app.config['SMS_API_KEY'] = os.getenv('SMS_API_KEY')
    app.config['WHATSAPP_API_URL'] = os.getenv('WHATSAPP_API_URL')
    app.config['WHATSAPP_API_KEY'] = os.getenv('WHATSAPP_API_KEY')
    app.config['BASE_URL'] = os.getenv('BASE_URL', 'http://localhost:5000')
    app.config['SETUP_KEY'] = os.getenv('SETUP_KEY')
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Validate critical environment variables
    for key in ['SETUP_KEY', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'SMTP_USERNAME', 'SMTP_PASSWORD']:
        if not app.config.get(key):
            logger.warning(f'{key} environment variable not set; some features may be disabled')

    # Initialize MongoDB client
    try:
        client = MongoClient(
            app.config['MONGO_URI'],
            serverSelectionTimeoutMS=5000,
            tls=True,
            tlsCAFile=certifi.where() if os.getenv('MONGO_CA_FILE') is None else os.getenv('MONGO_CA_FILE'),
            maxPoolSize=50,
            minPoolSize=5
        )
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['mongo'] = client
        client.admin.command('ping')
        logger.info('MongoDB client initialized successfully')
        
        def shutdown_mongo_client():
            """Close MongoDB client connection."""
            try:
                mongo = app.extensions.get('mongo')
                if mongo:
                    mongo.close()
                    logger.info('MongoDB client closed')
            except Exception as e:
                logger.error(f'Error closing MongoDB client: {str(e)}', exc_info=True)
        
    except Exception as e:
        logger.error(f'MongoDB connection test failed: {str(e)}', exc_info=True)
        raise RuntimeError(f'Failed to connect to MongoDB: {str(e)}')
    
    # Initialize extensions
    setup_logging(app)
    compress.init_app(app)
    csrf.init_app(app)
    mail = Mail()
    mail.init_app(app)
    limiter.init_app(app)
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    babel.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'users.login'

    # Enhanced session handling
    @app.before_request
    def before_request():
        """Store user_id and email in session for authenticated users."""
        if current_user.is_authenticated:
            session['user_id'] = current_user.id
            session['email'] = current_user.email
            logger.debug(f"Stored user_id: {current_user.id}, email: {current_user.email} in session")
        else:
            session.pop('user_id', None)
            session.pop('email', None)

    # User loader callback for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        """Load user from MongoDB using user_id."""
        try:
            if not validate_user_id(user_id):
                logger.warning(f"Invalid user_id in user_loader: {user_id}")
                return None
            with app.app_context():
                db = app.extensions['mongo']['ficodb']
                user = get_user(db, user_id)
                if not user:
                    logger.warning(f"User not found: {user_id}")
                    return None
                if not validate_email(user.email):
                    logger.warning(f"Invalid email for user {user_id}: {user.email}")
                    return None
                return User(
                    id=user.id,
                    email=user.email,
                    display_name=user.display_name,
                    role=user.role,
                    is_admin=user.is_admin,
                    setup_complete=user.setup_complete,
                    coin_balance=user.coin_balance,
                    ficore_credit_balance=user.ficore_credit_balance,
                    language=user.language,
                    dark_mode=user.dark_mode
                )
        except Exception as e:
            logger.error(f"Error loading user {user_id}: {str(e)}", exc_info=True)
            return None

    # Initialize MongoDB and other components
    try:
        with app.app_context():
            initialize_app_data(app)
            logger.info('Database initialized successfully')

            scheduler = init_scheduler(app, app.extensions['mongo']['ficodb'])
            app.config['SCHEDULER'] = scheduler
            logger.info('Scheduler initialized successfully')
            
            def shutdown_scheduler():
                """Shutdown scheduler gracefully."""
                try:
                    if scheduler and getattr(scheduler, 'running', False):
                        scheduler.shutdown(wait=True)
                        logger.info('Scheduler shutdown successfully')
                except Exception as e:
                    logger.error(f'Error shutting down scheduler: {str(e)}', exc_info=True)

            personal_finance_collections = [
                'budgets', 'bills', 'bill_reminders'
            ]
            db = app.extensions['mongo']['ficodb']
            for collection_name in personal_finance_collections:
                if collection_name not in db.list_collection_names():
                    db.create_collection(collection_name)
                    logger.info(f'Created collection: {collection_name}')
            
            # Initialize tax-related collections
            try:
                initialize_tax_data(db, trans)
                logger.info('Tax-related data initialized')
            except Exception as e:
                logger.error(f'Failed to initialize tax-related data: {str(e)}', exc_info=True)
                raise
            
            try:
                db.bills.create_index([('user_id', 1), ('email', 1), ('due_date', 1)])
                db.bills.create_index([('created_at', -1)])
                db.bills.create_index([('due_date', 1)])
                db.bills.create_index([('status', 1)])
                db.budgets.create_index([('user_id', 1), ('email', 1), ('created_at', -1)])
                db.budgets.create_index([('created_at', -1)])
                db.bill_reminders.create_index([('user_id', 1), ('email', 1), ('sent_at', -1)])
                db.bill_reminders.create_index([('notification_id', 1)])
                db.records.create_index([('user_id', 1), ('email', 1), ('type', 1), ('created_at', -1)])
                db.cashflows.create_index([('user_id', 1), ('email', 1), ('type', 1), ('created_at', -1)])
                logger.info('Created indexes for collections')
            except Exception as e:
                logger.warning(f'Some indexes may already exist: {str(e)}')
            
            admin_email = os.getenv('ADMIN_EMAIL', 'ficoreafrica@gmail.com')
            admin_password = os.getenv('ADMIN_PASSWORD')
            if not admin_password:
                logger.error('ADMIN_PASSWORD environment variable is not set')
                raise ValueError('ADMIN_PASSWORD must be set')
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            if not validate_email(admin_email):
                logger.error(f'Invalid admin email: {admin_email}')
                raise ValueError('Invalid ADMIN_EMAIL format')
            admin_user = get_user_by_email(db, admin_email)
            if not admin_user:
                user_data = {
                    'email': admin_email.lower(),
                    'password': generate_password_hash(admin_password),
                    'role': 'admin',
                    'display_name': admin_username,
                    'is_admin': True,
                    'setup_complete': True,
                    'language': 'en',
                    'created_at': datetime.utcnow()
                }
                admin_user = create_user(db, user_data)
                logger.info(f'Admin user created with ID: {admin_user.id}, email: {admin_email}')
            else:
                logger.info(f'Admin user already exists with ID: {admin_user.id}, email: {admin_email}')
    except Exception as e:
        logger.error(f'Error in create_app initialization: {str(e)}', exc_info=True)
        raise

    # Register blueprints
    from users.routes import users_bp
    from agents.routes import agents_bp
    from creditors.routes import creditors_bp
    from dashboard.routes import dashboard_bp
    from debtors.routes import debtors_bp
    from payments.routes import payments_bp
    from receipts.routes import receipts_bp
    from reports.routes import reports_bp
    from settings.routes import settings_bp
    from personal import personal_bp
    from general.routes import general_bp
    from admin.routes import admin_bp
    from taxation.routes import taxation_bp
    from ai import ai_bp
    
    app.register_blueprint(users_bp, url_prefix='/users')
    app.register_blueprint(agents_bp, url_prefix='/agents')
    app.register_blueprint(taxation_bp, url_prefix='/taxation')
    app.register_blueprint(credits_bp, url_prefix='/credits')
    app.register_blueprint(creditors_bp, url_prefix='/creditors')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(debtors_bp, url_prefix='/debtors')
    app.register_blueprint(payments_bp, url_prefix='/payments')
    app.register_blueprint(receipts_bp, url_prefix='/receipts')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(settings_bp, url_prefix='/settings')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(personal_bp)
    app.register_blueprint(general_bp, url_prefix='/general')
    app.register_blueprint(business, url_prefix='/business')
    app.register_blueprint(ai_bp)
    logger.info('Registered all blueprints')

    utils.initialize_tools_with_urls(app)
    logger.info('Initialized tools and navigation with resolved URLs')

    app.jinja_env.globals.update(
        FACEBOOK_URL=app.config.get('FACEBOOK_URL', 'https://facebook.com/ficoreafrica'),
        TWITTER_URL=app.config.get('TWITTER_URL', 'https://x.com/ficoreafrica'),
        LINKEDIN_URL=app.config.get('LINKEDIN_URL', 'https://linkedin.com/company/ficoreafrica'),
        FEEDBACK_FORM_URL=app.config.get('FEEDBACK_FORM_URL', '#'),
        WAITLIST_FORM_URL=app.config.get('WAITLIST_FORM_URL', '#'),
        CONSULTANCY_FORM_URL=app.config.get('CONSULTANCY_FORM_URL', '#'),
        trans=trans,
        trans_function=utils.trans_function,
        get_translations=get_translations,
        is_admin=lambda: current_user.is_admin if current_user.is_authenticated else False
    )
    
    @app.template_filter('safe_nav')
    def safe_nav(value):
        """Ensure navigation items have valid icons and structure."""
        try:
            if not isinstance(value, dict) or 'icon' not in value:
                logger.warning(f'Invalid navigation item: {value}')
                return {'icon': 'bi-question-circle', 'label': value.get('label', ''), 'url': value.get('url', '#')}
            if not value.get('icon', '').startswith('bi-'):
                logger.warning(f'Invalid icon in navigation item: {value.get("icon")}')
                value['icon'] = 'bi-question-circle'
            return value
        except Exception as e:
            logger.error(f'Navigation rendering error: {str(e)}', exc_info=True)
            return {'icon': 'bi-question-circle', 'label': str(value), 'url': '#'}

    @app.template_filter('format_number')
    def format_number(value):
        """Format numbers with two decimal places."""
        try:
            if isinstance(value, (int, float)):
                return f'{float(value):,.2f}'
            return str(value)
        except (ValueError, TypeError) as e:
            logger.warning(f'Error formatting number {value}: {str(e)}')
            return str(value)

    app.jinja_env.filters['format_currency'] = utils.format_currency

    @app.template_filter('format_datetime')
    def format_datetime(value):
        """Format datetime based on user language."""
        try:
            lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
            format_str = '%B %d, %Y, %I:%M %p' if lang == 'en' else '%d %B %Y, %I:%M %p'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime('%B %d, %Y' if lang == 'en' else '%d %B %Y')
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d')
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f'Error formatting datetime {value}: {str(e)}')
            return str(value)
    
    @app.template_filter('format_date')
    def format_date(value):
        """Format date based on user language."""
        try:
            lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
            format_str = '%Y-%m-%d' if lang == 'en' else '%d-%m-%Y'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime(format_str)
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d').date()
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f'Error formatting date {value}: {str(e)}')
            return str(value)
    
    @app.template_filter('trans')
    def trans_filter(key, **kwargs):
        """Translate text based on user language."""
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        translation = utils.trans(key, lang=lang, **kwargs)
        if translation == key:
            logger.warning(f'Missing translation for key="{key}" in lang="{lang}"')
            return key
        return translation
        
    @app.context_processor
    def inject_role_nav():
        """Inject navigation items based on user role."""
        tools_for_template = []
        explore_features_for_template = []
        bottom_nav_items = []
        try:
            with app.app_context():
                if current_user.is_authenticated:
                    if current_user.role == 'personal':
                        tools_for_template = utils.PERSONAL_TOOLS
                        explore_features_for_template = utils.PERSONAL_EXPLORE_FEATURES
                        bottom_nav_items = utils.PERSONAL_NAV
                    elif current_user.role == 'trader':
                        tools_for_template = utils.BUSINESS_TOOLS
                        explore_features_for_template = utils.BUSINESS_EXPLORE_FEATURES
                        bottom_nav_items = utils.BUSINESS_NAV
                    elif current_user.role == 'agent':
                        tools_for_template = utils.AGENT_TOOLS
                        explore_features_for_template = utils.AGENT_EXPLORE_FEATURES
                        bottom_nav_items = utils.AGENT_NAV
                    elif current_user.role == 'admin':
                        tools_for_template = utils.ALL_TOOLS
                        explore_features_for_template = utils.ADMIN_EXPLORE_FEATURES
                        bottom_nav_items = utils.ADMIN_NAV
                else:
                    explore_features_for_template = utils.get_explore_features()
                for nav_list in [tools_for_template, explore_features_for_template, bottom_nav_items]:
                    for item in nav_list:
                        if not isinstance(item, dict) or 'icon' not in item or not item['icon'].startswith('bi-'):
                            logger.warning(f'Invalid or missing icon in navigation item: {item}')
                            item['icon'] = 'bi-question-circle'
                logger.info('Navigation data injected for template rendering')
        except Exception as e:
            logger.error(f'Error in inject_role_nav: {str(e)}', exc_info=True)
        return dict(
            tools_for_template=tools_for_template,
            explore_features_for_template=explore_features_for_template,
            bottom_nav_items=bottom_nav_items,
            t=trans,
            lang=getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en',
            format_currency=utils.format_currency,
            format_date=utils.format_date
        )
    
    @app.context_processor
    def inject_globals():
        """Inject global variables for templates."""
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        def context_trans(key, **kwargs):
            used_lang = kwargs.pop('lang', lang)
            return utils.trans(
                key,
                lang=used_lang,
                logger=g.get('logger', logger) if has_request_context() else logger,
                **kwargs
            )
        supported_languages = app.config.get('SUPPORTED_LANGUAGES', ['en', 'ha'])
        return {
            'google_client_id': app.config.get('GOOGLE_CLIENT_ID', ''),
            'trans': context_trans,
            'get_translations': get_translations,
            'current_year': datetime.now().year,
            'LINKEDIN_URL': app.config.get('LINKEDIN_URL', 'https://linkedin.com/company/ficoreafrica'),
            'TWITTER_URL': app.config.get('TWITTER_URL', 'https://x.com/ficoreafrica'),
            'FACEBOOK_URL': app.config.get('FACEBOOK_URL', 'https://facebook.com/ficoreafrica'),
            'FEEDBACK_FORM_URL': app.config.get('FEEDBACK_FORM_URL', '#'),
            'WAITLIST_FORM_URL': app.config.get('WAITLIST_FORM_URL', '#'),
            'CONSULTANCY_FORM_URL': app.config.get('CONSULTANCY_FORM_URL', '#'),
            'current_lang': lang,
            'current_user': current_user if has_request_context() else None,
            'available_languages': [
                {'code': code, 'name': utils.trans(f'lang_{code}', lang=lang, default=code.capitalize())}
                for code in supported_languages
            ],
            'dialogflow_agent_id': app.config.get('DIALOGFLOW_PROJECT_ID', 'ficoreassistant-kywl')
        }
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to responses."""
        if not request.path.startswith('/api'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com https://www.gstatic.com https://www.gstatic.com/dialogflow-console/;"
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com;"
            "img-src 'self' data:;"
            "connect-src 'self' https://api.ficore.app;"
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com;"
        )
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=3600; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
    
    @app.route('/change-language', methods=['POST'])
    @limiter.limit('10 per minute')
    @validate_identity
    def change_language():
        """Change user language preference."""
        try:
            data = request.get_json()
            new_lang = data.get('language', 'en')
            supported_languages = app.config.get('SUPPORTED_LANGUAGES', ['en', 'ha'])
            if new_lang not in supported_languages:
                logger.warning(f'Invalid language requested: {new_lang}')
                return jsonify({
                    'success': False, 
                    'message': utils.trans('lang_invalid')
                }), 400
            if current_user.is_authenticated:
                try:
                    db = app.extensions['mongo']['ficodb']
                    update_user(db, current_user.id, current_user.email, {'language': new_lang})
                    current_user.language = new_lang
                    session['language'] = new_lang
                    logger.info(f"Updated session language to {new_lang} for user {current_user.id}/{current_user.email}")
                except Exception as e:
                    logger.warning(f'Could not update user language preference: {str(e)}')
                    return jsonify({
                        'success': False,
                        'message': utils.trans('error_general')
                    }), 500
            logger.info(f'Language changed to {new_lang} for user {current_user.id if current_user.is_authenticated else "anonymous"}/{current_user.email if current_user.is_authenticated else "no-email"}')
            return jsonify({
                'success': True, 
                'message': utils.trans('lang_change_success', lang=new_lang)
            })
        except Exception as e:
            logger.error(f'Error changing language: {str(e)}')
            return jsonify({
                'success': False, 
                'message': utils.trans('error_general')
            }), 500
    
    @app.route('/', methods=['GET', 'HEAD'])
    def index():
        """Serve the main landing page or redirect based on user role."""
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        logger.info(f'Serving index page, authenticated: {current_user.is_authenticated}')
        if request.method == 'HEAD':
            return '', 200
        if current_user.is_authenticated:
            if not validate_user_id(current_user.id) or not validate_email(current_user.email):
                logger.warning(f"Invalid user identity: {current_user.id}/{current_user.email}")
                logout_user()
                return redirect(url_for('users.login'))
            if current_user.role == 'agent':
                return redirect(url_for('agents_bp.agent_portal'))
            elif current_user.role == 'trader':
                return redirect(url_for('business.home'))
            elif current_user.role == 'admin':
                try:
                    return redirect(url_for('dashboard.index'))
                except:
                    return redirect(url_for('general_bp.home'))
            elif current_user.role == 'personal':
                return redirect(url_for('personal.index'))
        return render_template('general/landingpage.html', title=utils.trans('home', lang=lang))
    
    @app.route('/general_dashboard')
    @login_required
    @validate_identity
    def general_dashboard():
        """Redirect to unified dashboard."""
        logger.info(f'Redirecting to unified dashboard for user {current_user.id}/{current_user.email}')
        return redirect(url_for('dashboard_bp.index'))
    
    @app.route('/business-agent-home')
    def business_agent_home():
        """Serve business-agent home page or redirect based on role."""
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        logger.info(f'Serving business-agent home, authenticated: {current_user.is_authenticated}')
        if current_user.is_authenticated:
            if not validate_user_id(current_user.id) or not validate_email(current_user.email):
                logger.warning(f"Invalid user identity: {current_user.id}/{current_user.email}")
                logout_user()
                return redirect(url_for('users.login'))
            if current_user.role == 'agent':
                return redirect(url_for('agents_bp.agent_portal'))
            elif current_user.role == 'trader':
                return redirect(url_for('business.home'))
            else:
                flash(utils.trans('no_permission'), 'error')
                return redirect(url_for('index'))
        try:
            logger.info('Serving public business-agent-home')
            return render_template(
                'general/home.html',
                is_public=True,
                title=utils.trans('business_home', lang=lang)
            )
        except TemplateNotFound as e:
            logger.error(f'Template not found: {str(e)}')
            return render_template(
                'personal/GENERAL/error.html',
                error=str(e),
                title=utils.trans('business_home', lang=lang)
            ), 404
    
    @app.route('/health')
    @limiter.limit('10 per minute')
    def health():
        """Check application health and MongoDB connection."""
        logger.info('Performing health check')
        status = {'status': 'healthy'}
        try:
            with app.app_context():
                app.extensions['mongo'].admin.command('ping')
            return jsonify(status), 200
        except Exception as e:
            logger.error(f'Health check failed: {str(e)}')
            status['status'] = 'unhealthy'
            status['details'] = str(e)
            return jsonify(status), 500
    
    @app.route('/api/translations/<lang>')
    @limiter.limit('10 per minute')
    def get_translations_api(lang):
        """Retrieve translations for a specific language."""
        try:
            supported_languages = app.config.get('SUPPORTED_LANGUAGES', ['en', 'ha'])
            if lang not in supported_languages:
                logger.warning(f'Invalid language requested: {lang}')
                return jsonify({'error': utils.trans('invalid_language')}), 400
            
            all_translations = get_all_translations()
            result = {}
            for module_name, module_translations in all_translations.items():
                if lang in module_translations:
                    result.update(module_translations[lang])
            
            return jsonify({'translations': result})
        except Exception as e:
            logger.error(f'Translation API error: {str(e)}')
            return jsonify({'error': utils.trans('error')}), 500
    
    @app.route('/api/translate')
    @limiter.limit('10 per minute')
    def api_translate():
        """Translate a specific key for a given language."""
        try:
            key = request.args.get('key')
            lang = request.args.get('lang', getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en')
            supported_languages = app.config.get('SUPPORTED_LANGUAGES', ['en', 'ha'])
            if not key:
                logger.warning('Missing translation key')
                return jsonify({'error': utils.trans('missing_key')}), 400
            if lang not in supported_languages:
                logger.warning(f'Invalid language requested: {lang}')
                return jsonify({'error': utils.trans('invalid_language')}), 400
            
            translation = utils.trans(key, lang=lang)
            return jsonify({'key': key, 'translation': translation, 'lang': lang})
        except Exception as e:
            logger.error(f'Translate API error: {str(e)}')
            return jsonify({'error': utils.trans('error')}), 500
    
    @app.route('/set_language/<lang>')
    @limiter.limit('10 per minute')
    @validate_identity
    def set_language(lang):
        """Set user language preference."""
        supported_languages = current_app.config.get('SUPPORTED_LANGUAGES', ['en', 'ha'])
        new_lang = lang if lang in supported_languages else 'en'
        try:
            if current_user.is_authenticated:
                if not validate_user_id(current_user.id) or not validate_email(current_user.email):
                    logger.warning(f"Invalid user identity: {current_user.id}/{current_user.email}")
                    logout_user()
                    return redirect(url_for('users.login'))
                try:
                    db = current_app.extensions['mongo']['ficodb']
                    update_user(db, current_user.id, current_user.email, {'language': new_lang})
                    current_user.language = new_lang
                    session['language'] = new_lang
                    logger.info(f"Updated session language to {new_lang} for user {current_user.id}/{current_user.email}")
                except Exception as e:
                    logger.warning(f'Could not update user language for user {current_user.id}/{current_user.email}: {str(e)}')
                    flash(utils.trans('invalid_lang', default='Could not update language'), 'danger')
                    return redirect(url_for('index'))
            logger.info(f'Set language to {new_lang} for user {current_user.id if current_user.is_authenticated else "anonymous"}/{current_user.email if current_user.is_authenticated else "no-email"}')
            flash(utils.trans('lang_updated', default='Language updated successfully'), 'success')
            redirect_url = request.referrer if utils.is_safe_referrer(request.referrer, request.host) else url_for('index')
            return redirect(redirect_url)
        except Exception as e:
            logger.error(f'Error setting language: {str(e)}')
            flash(utils.trans('invalid_lang', default='Could not update language'), 'danger')
            return redirect(url_for('index'))
    
    @app.route('/setup', methods=['GET'])
    @limiter.limit('2 per minute;10 per hour')
    @validate_identity
    def setup_database_route():
        """Initialize database with setup key verification."""
        setup_key = request.args.get('key')
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        if not app.config.get('SETUP_KEY') or setup_key != app.config['SETUP_KEY']:
            logger.warning(f'Invalid setup key: {setup_key}')
            try:
                return render_template(
                    'error/403.html',
                    content=utils.trans('access_denied'),
                    title=utils.trans('access_denied', lang=lang)
                ), 403
            except TemplateNotFound as e:
                logger.error(f'Template not found: {str(e)}')
                return render_template(
                    'personal/GENERAL/error.html',
                    content=utils.trans('access_denied'),
                    title=utils.trans('access_denied', lang=lang)
                ), 403
        try:
            with app.app_context():
                initialize_app_data(app)
            flash(utils.trans('db_setup_success'), 'success')
            logger.info('Database setup completed')
            return redirect(url_for('index'))
        except Exception as e:
            flash(utils.trans('db_setup_error'), 'danger')
            logger.error(f'DB setup error: {str(e)}')
            try:
                return render_template(
                    'personal/GENERAL/error.html',
                    content=utils.trans('server_error'),
                    title=utils.trans('error', lang=lang)
                ), 500
            except TemplateNotFound as e:
                logger.error(f'Template not found: {str(e)}')
                return render_template(
                    'personal/GENERAL/error.html',
                    content=utils.trans('server_error'),
                    title=utils.trans('error', lang=lang)
                ), 500
    
    @app.route('/static/<path:filename>')
    def static_files(filename):
        """Serve static files with security checks."""
        if '..' in filename or filename.startswith('/'):
            logger.warning(f'Invalid static path: {filename}')
            abort(404)
        try:
            response = send_from_directory('static', filename)
            if filename.endswith('.woff2'):
                response.headers['Content-Type'] = 'font/woff2'
                response.headers['Cache-Control'] = 'public, max-age=604800'
            else:
                response.headers['Cache-Control'] = 'public, max-age=3600'
            return response
        except FileNotFoundError:
            logger.error(f'Static file not found: {filename}')
            abort(404)
    
    @app.route('/static_personal/<path:filename>')
    def static_personal(filename):
        """Serve personal static files with security checks."""
        allowed_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg'}
        allowed_mime_types = {
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.ico': 'image/x-icon',
            '.svg': 'image/svg+xml'
        }
        file_ext = os.path.splitext(filename)[1].lower()
        if '..' in filename or filename.startswith('/') or file_ext not in allowed_extensions:
            logger.warning(f'Invalid personal file path or ext: {filename}')
            abort(404)
        try:
            response = send_from_directory('static_personal', filename)
            response.headers['Content-Type'] = allowed_mime_types.get(file_ext, 'application/octet-stream')
            if file_ext in {'.css', '.js'}:
                response.headers['Cache-Control'] = 'public, max-age=3600'
            elif file_ext in {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg'}:
                response.headers['Cache-Control'] = 'public, max-age=604800'
            return response
        except FileNotFoundError:
            logger.error(f'File not found: {filename}')
            abort(404)
    
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon."""
        try:
            return send_from_directory(app.static_folder, 'img/favicon.ico')
        except FileNotFoundError:
            logger.error('Favicon not found')
            abort(404)
    
    @app.route('/service-worker.js')
    def service_worker():
        """Serve service worker script."""
        try:
            return app.send_static_file('js/service-worker.js')
        except FileNotFoundError:
            logger.error('Service worker not found')
            abort(404)
    
    @app.route('/manifest.json')
    def manifest():
        """Serve web app manifest."""
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        manifest_data = {
            "name": "FiCore App",
            "short_name": "FiCore",
            "description": "Financial management for personal and business use",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#ffffff",
            "theme_color": "#007bff",
            "icons": [
                {
                    "src": "/static/img/icon-192x192.png",
                    "sizes": "192x192",
                    "type": "image/png"
                },
                {
                    "src": "/static/img/icon-512x512.png",
                    "sizes": "512x512",
                    "type": "image/png"
                }
            ],
            "lang": lang,
            "dir": "ltr",
            "orientation": "portrait",
            "scope": "/",
            "related_applications": [],
            "prefer_related_applications": False
        }
        return jsonify(manifest_data)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Handle CSRF errors."""
        logger.error(f'CSRF error: {str(e)}')
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        try:
            return render_template(
                'error/403.html', 
                error=utils.trans('csrf_error'), 
                title=utils.trans('csrf_error', lang=lang)
            ), 400
        except TemplateNotFound:
            return render_template(
                'personal/GENERAL/error.html', 
                error=utils.trans('csrf_error'), 
                title=utils.trans('csrf_error', lang=lang)
            ), 400

    @app.errorhandler(404)
    def page_not_found(e):
        """Handle 404 errors."""
        logger.error(f'Not found: {request.url}')
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        try:
            return render_template(
                'personal/GENERAL/404.html', 
                error=str(e), 
                title=utils.trans('not_found', lang=lang)
            ), 404
        except TemplateNotFound:
            return render_template(
                'personal/GENERAL/error.html', 
                error=str(e), 
                title=utils.trans('not_found', lang=lang)
            ), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        """Handle 500 errors."""
        logger.error(f'Server error: {str(e)}')
        lang = getattr(current_user, 'language', 'en') if current_user.is_authenticated else 'en'
        try:
            return render_template(
                'personal/GENERAL/error.html', 
                error=str(e), 
                title=utils.trans('server_error', lang=lang)
            ), 500
        except TemplateNotFound:
            return render_template(
                'personal/GENERAL/error.html', 
                error=str(e), 
                title=utils.trans('server_error', lang=lang)
            ), 500

    scheduler_shutdown_done = False

    @app.teardown_appcontext
    def cleanup_scheduler(exception):
        """Cleanup scheduler on app context teardown."""
        nonlocal scheduler_shutdown_done
        scheduler = app.config.get('SCHEDULER')
        if scheduler and scheduler.running and not scheduler_shutdown_done:
            try:
                scheduler.shutdown()
                logger.info('Scheduler shutdown')
                scheduler_shutdown_done = True
            except Exception as e:
                logger.error(f'Scheduler shutdown error: {str(e)}')

    return app

if __name__ == '__main__':
    logger.info('Starting Flask application')
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
