from flask import Blueprint, request, session, redirect, url_for, render_template, flash, current_app, jsonify, Response, Flask
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, FloatField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Email
from flask_login import current_user, login_required
from datetime import datetime, timedelta
from helpers.branding_helpers import draw_ficore_pdf_header
from bson import ObjectId
from pymongo import errors
from utils import get_mongo_db, requires_role, logger, clean_currency, check_ficore_credit_balance, is_admin, format_date, format_currency
from translations import trans
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from contextlib import nullcontext
import threading
import re
import uuid
from models import log_tool_usage
from session_utils import create_anonymous_session
from app import app

shopping_bp = Blueprint(
    'shopping',
    __name__,
    template_folder='templates/personal/SHOPPING',
    url_prefix='/shopping'
)

csrf = CSRFProtect()

def auto_categorize_item(item_name):
    item_name = item_name.lower().strip()
    categories = {
        'fruits': ['apple', 'banana', 'orange', 'mango', 'pineapple', 'berry', 'grape'],
        'vegetables': ['carrot', 'potato', 'tomato', 'onion', 'spinach', 'lettuce'],
        'dairy': ['milk', 'cheese', 'yogurt', 'butter', 'cream'],
        'meat': ['chicken', 'beef', 'pork', 'fish', 'egg'],
        'grains': ['rice', 'bread', 'pasta', 'flour', 'cereal'],
        'beverages': ['juice', 'soda', 'water', 'tea', 'coffee'],
        'household': ['detergent', 'soap', 'tissue', 'paper towel'],
        'other': []
    }
    for category, keywords in categories.items():
        if any(keyword in item_name for keyword in keywords):
            return category
    return 'other'

def deduct_ficore_credits(db, user_id, amount, action, item_id=None, mongo_session=None):
    try:
        if amount <= 0:
            logger.error(f"Invalid deduction amount {amount} for user {user_id}, action: {action}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return False
        user = db.users.find_one({'_id': user_id}, session=mongo_session)
        if not user:
            logger.error(f"User {user_id} not found for credit deduction, action: {action}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return False
        current_balance = user.get('ficore_credit_balance', 0)
        if current_balance < amount:
            logger.warning(f"Insufficient credits for user {user_id}: required {amount}, available {current_balance}, action: {action}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return False
        session_to_use = mongo_session if mongo_session else db.client.start_session()
        owns_session = not mongo_session
        try:
            with session_to_use.start_transaction() if not mongo_session else nullcontext():
                result = db.users.update_one(
                    {'_id': user_id},
                    {'$inc': {'ficore_credit_balance': -amount}},
                    session=session_to_use
                )
                if result.modified_count == 0:
                    logger.error(f"Failed to deduct {amount} credits for user {user_id}, action: {action}: No documents modified", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    raise ValueError(f"Failed to update user balance for {user_id}")
                transaction = {
                    '_id': ObjectId(),
                    'user_id': user_id,
                    'action': action,
                    'amount': -amount,
                    'item_id': str(item_id) if item_id else None,
                    'timestamp': datetime.utcnow(),
                    'session_id': session.get('sid', 'no-session-id'),
                    'status': 'completed'
                }
                db.ficore_credit_transactions.insert_one(transaction, session=session_to_use)
            logger.info(f"Deducted {amount} Ficore Credits for {action} by user {user_id}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return True
        except (ValueError, errors.PyMongoError) as e:
            logger.error(f"Transaction aborted for user {user_id}, action: {action}: {str(e)}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr, 'stack_trace': traceback.format_exc()})
            return False
        finally:
            if owns_session:
                session_to_use.end_session()
    except Exception as e:
        logger.error(f"Unexpected error deducting {amount} Ficore Credits for {action} by user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr, 'stack_trace': traceback.format_exc()})
        return False

def custom_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated or session.get('is_anonymous', False):
            return f(*args, **kwargs)
        return redirect(url_for('users.login', next=request.url))
    return decorated_function

class ShoppingListForm(FlaskForm):
    name = StringField(
        trans('shopping_list_name', default='List Name'),
        validators=[DataRequired(message=trans('shopping_name_required', default='List name is required'))]
    )
    budget = FloatField(
        trans('shopping_budget', default='Budget'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('shopping_budget_required', default='Budget is required')),
            NumberRange(min=0, max=10000000000, message=trans('shopping_budget_max', default='Budget must be between 0 and 10 billion'))
        ]
    )
    submit = SubmitField(trans('shopping_submit', default='Create List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('shopping_list_name', lang) or 'List Name'
        self.budget.label.text = trans('shopping_budget', lang) or 'Budget'
        self.submit.label.text = trans('shopping_submit', lang) or 'Create List'

class ShoppingListEditForm(FlaskForm):
    name = StringField(
        trans('shopping_list_name', default='List Name'),
        validators=[DataRequired(message=trans('shopping_name_required', default='List name is required'))]
    )
    budget = FloatField(
        trans('shopping_budget', default='Budget'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('shopping_budget_required', default='Budget is required')),
            NumberRange(min=0, max=10000000000, message=trans('shopping_budget_max', default='Budget must be between 0 and 10 billion'))
        ]
    )
    submit = SubmitField(trans('shopping_edit_submit', default='Update List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('shopping_list_name', lang) or 'List Name'
        self.budget.label.text = trans('shopping_budget', lang) or 'Budget'
        self.submit.label.text = trans('shopping_edit_submit', lang) or 'Update List'

class ShoppingItemForm(FlaskForm):
    name = StringField(
        trans('shopping_item_name', default='Item Name'),
        validators=[DataRequired(message=trans('shopping_item_name_required', default='Item name is required'))]
    )
    quantity = IntegerField(
        trans('shopping_quantity', default='Quantity'),
        validators=[
            DataRequired(message=trans('shopping_quantity_required', default='Quantity is required')),
            NumberRange(min=1, max=1000, message=trans('shopping_quantity_range', default='Quantity must be between 1 and 1000'))
        ]
    )
    price = FloatField(
        trans('shopping_price', default='Price'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('shopping_price_required', default='Price is required')),
            NumberRange(min=0, max=1000000, message=trans('shopping_price_range', default='Price must be between 0 and 1 million'))
        ]
    )
    unit = SelectField(
        trans('shopping_unit', default='Unit'),
        choices=[
            ('piece', trans('shopping_unit_piece', default='Piece')),
            ('carton', trans('shopping_unit_carton', default='Carton')),
            ('kg', trans('shopping_unit_kg', default='Kilogram')),
            ('liter', trans('shopping_unit_liter', default='Liter')),
            ('pack', trans('shopping_unit_pack', default='Pack')),
            ('other', trans('shopping_unit_other', default='Other'))
        ],
        validators=[DataRequired(message=trans('shopping_unit_required', default='Unit is required'))]
    )
    store = StringField(
        trans('shopping_store', default='Store'),
        validators=[DataRequired(message=trans('shopping_store_required', default='Store is required'))]
    )
    category = SelectField(
        trans('shopping_category', default='Category'),
        choices=[
            ('fruits', trans('shopping_category_fruits', default='Fruits')),
            ('vegetables', trans('shopping_category_vegetables', default='Vegetables')),
            ('dairy', trans('shopping_category_dairy', default='Dairy')),
            ('meat', trans('shopping_category_meat', default='Meat')),
            ('grains', trans('shopping_category_grains', default='Grains')),
            ('beverages', trans('shopping_category_beverages', default='Beverages')),
            ('household', trans('shopping_category_household', default='Household')),
            ('other', trans('shopping_category_other', default='Other'))
        ]
    )
    status = SelectField(
        trans('shopping_status', default='Status'),
        choices=[
            ('to_buy', trans('shopping_status_to_buy', default='To Buy')),
            ('bought', trans('shopping_status_bought', default='Bought'))
        ]
    )
    frequency = IntegerField(
        trans('shopping_frequency', default='Frequency (days)'),
        validators=[
            DataRequired(message=trans('shopping_frequency_required', default='Frequency is required')),
            NumberRange(min=1, max=365, message=trans('shopping_frequency_range', default='Frequency must be between 1 and 365 days'))
        ]
    )
    submit = SubmitField(trans('shopping_item_submit', default='Add Item'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('shopping_item_name', lang) or 'Item Name'
        self.quantity.label.text = trans('shopping_quantity', lang) or 'Quantity'
        self.price.label.text = trans('shopping_price', lang) or 'Price'
        self.unit.label.text = trans('shopping_unit', lang) or 'Unit'
        self.store.label.text = trans('shopping_store', lang) or 'Store'
        self.category.label.text = trans('shopping_category', lang) or 'Category'
        self.status.label.text = trans('shopping_status', lang) or 'Status'
        self.frequency.label.text = trans('shopping_frequency', lang) or 'Frequency (days)'
        self.submit.label.text = trans('shopping_item_submit', lang) or 'Add Item'

class ShareListForm(FlaskForm):
    email = StringField(
        trans('shopping_collaborator_email', default='Collaborator Email'),
        validators=[
            DataRequired(message=trans('shopping_email_required', default='Email is required')),
            Email(message=trans('shopping_invalid_email', default='Invalid email address'))
        ]
    )
    submit = SubmitField(trans('shopping_share_submit', default='Share List'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.email.label.text = trans('shopping_collaborator_email', lang) or 'Collaborator Email'
        self.submit.label.text = trans('shopping_share_submit', lang) or 'Share List'

@shopping_bp.route('/main', methods=['GET', 'POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def main():
    if 'sid' not in session:
        create_anonymous_session()
        session['is_anonymous'] = True
        logger.debug(f"New anonymous session created with sid: {session['sid']}", extra={'session_id': session['sid']})
    session.permanent = True
    session.modified = True
    list_form = ShoppingListForm()
    item_form = ShoppingItemForm()
    share_form = ShareListForm()
    edit_form = ShoppingListEditForm()
    db = get_mongo_db()

    valid_tabs = ['create-list', 'dashboard', 'manage-list']
    active_tab = request.args.get('tab', 'create-list')
    if active_tab not in valid_tabs:
        active_tab = 'create-list'

    try:
        log_tool_usage(
            tool_name='shopping',
            db=db,
            user_id=current_user.id if current_user.is_authenticated else None,
            session_id=session.get('sid', 'no-session-id'),
            action='main_view'
        )
    except Exception as e:
        logger.error(f"Failed to log tool usage: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id')})
        flash(trans('shopping_log_error', default='Error logging shopping activity. Please try again.'), 'warning')

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)} if current_user.is_authenticated else {'session_id': session['sid']}
    lists = []
    latest_list = None
    categories = {}
    items = []

    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'create_list' and list_form.validate_on_submit():
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for creating shopping list by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to create a list. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                try:
                    log_tool_usage(
                        tool_name='shopping',
                        db=db,
                        user_id=current_user.id if current_user.is_authenticated else None,
                        session_id=session.get('sid', 'no-session-id'),
                        action='create_shopping_list'
                    )
                except Exception as e:
                    logger.error(f"Failed to log shopping list creation: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_log_error', default='Error logging shopping list creation. Continuing with submission.'), 'warning')

                list_data = {
                    '_id': ObjectId(),
                    'name': list_form.name.data,
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session['sid'],
                    'budget': list_form.budget.data,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'collaborators': [],
                    'items': [],
                    'total_spent': 0.0,
                    'status': 'active'
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.shopping_lists.insert_one(list_data, session=mongo_session)
                            if current_user.is_authenticated and not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, 0.1, 'create_shopping_list', list_data['_id'], mongo_session):
                                    db.shopping_lists.delete_one({'_id': list_data['_id']}, session=mongo_session)
                                    logger.error(f"Failed to deduct 0.1 Ficore Credits for creating list {list_data['_id']} by user {current_user.id}", 
                                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                    flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for creating list.'), 'danger')
                                    return redirect(url_for('personal.shopping.main', tab='create-list'))
                    logger.info(f"Created shopping list {list_data['_id']} for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_created', default='Shopping list created successfully!'), 'success')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                except Exception as e:
                    logger.error(f"Failed to save shopping list {list_data['_id']}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_error', default='Error saving shopping list.'), 'danger')

            elif action == 'add_item' and item_form.validate_on_submit():
                list_id = request.form.get('list_id')
                if not ObjectId.is_valid(list_id):
                    flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                if not shopping_list:
                    flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for adding item to list {list_id} by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to add an item. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                item_data = {
                    '_id': ObjectId(),
                    'list_id': list_id,
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session['sid'],
                    'name': item_form.name.data,
                    'quantity': item_form.quantity.data,
                    'price': item_form.price.data,
                    'unit': item_form.unit.data,
                    'category': item_form.category.data,
                    'status': item_form.status.data,
                    'store': item_form.store.data,
                    'frequency': item_form.frequency.data,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.shopping_items.insert_one(item_data, session=mongo_session)
                            db.shopping_lists.update_one(
                                {'_id': ObjectId(list_id)},
                                {'$inc': {'total_spent': float(item_form.price.data * item_form.quantity.data)}, '$set': {'updated_at': datetime.utcnow()}},
                                session=mongo_session
                            )
                            if current_user.is_authenticated and not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, 0.1, 'add_shopping_item', item_data['_id'], mongo_session):
                                    db.shopping_items.delete_one({'_id': item_data['_id']}, session=mongo_session)
                                    logger.error(f"Failed to deduct 0.1 Ficore Credits for adding item {item_data['_id']} to list {list_id}", 
                                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                    flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for adding item.'), 'danger')
                                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                    flash(trans('shopping_item_added', default='Item added successfully!'), 'success')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                except Exception as e:
                    logger.error(f"Failed to add item to list {list_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_item_error', default='Error adding item.'), 'danger')

            elif action == 'share_list' and share_form.validate_on_submit():
                list_id = request.form.get('list_id')
                if not ObjectId.is_valid(list_id):
                    flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                if not shopping_list:
                    flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                collaborator = db.users.find_one({'email': share_form.email.data})
                if not collaborator:
                    flash(trans('shopping_user_not_found', default='User with this email not found.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                try:
                    db.shopping_lists.update_one(
                        {'_id': ObjectId(list_id)},
                        {'$addToSet': {'collaborators': share_form.email.data}, '$set': {'updated_at': datetime.utcnow()}}
                    )
                    logger.info(f"Shared list {list_id} with {share_form.email.data}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_shared', default='List shared successfully!'), 'success')
                except Exception as e:
                    logger.error(f"Error sharing list {list_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_share_error', default='Error sharing list.'), 'danger')
                return redirect(url_for('personal.shopping.main', tab='dashboard'))

            elif action == 'delete_list':
                list_id = request.form.get('list_id')
                if not ObjectId.is_valid(list_id):
                    flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                if not shopping_list:
                    flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.5, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for deleting list {list_id} by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to delete a list. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                deletion_data = {
                    'list_id': list_id,
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session['sid'],
                    'created_at': datetime.utcnow(),
                    'expires_at': datetime.utcnow() + timedelta(seconds=20)
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.pending_deletions.insert_one(deletion_data, session=mongo_session)
                            if current_user.is_authenticated and not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, 0.5, 'delete_shopping_list', list_id, mongo_session):
                                    logger.error(f"Failed to deduct 0.5 Ficore Credits for deleting list {list_id} by user {current_user.id}", 
                                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                    flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for deleting list.'), 'danger')
                                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                            threading.Thread(target=process_delayed_deletion, args=(list_id, current_user.id if current_user.is_authenticated else None, session['sid'])).start()
                    logger.info(f"Initiated delayed deletion for shopping list {list_id}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_deletion_initiated', default='Shopping list deletion initiated. Will delete in 20 seconds.'), 'success')
                except Exception as e:
                    logger.error(f"Error initiating deletion of list {list_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_error', default='Error initiating deletion.'), 'danger')
                return redirect(url_for('personal.shopping.main', tab='dashboard'))

            elif action == 'save_list':
                list_id = request.form.get('list_id')
                if not ObjectId.is_valid(list_id):
                    flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                if not shopping_list:
                    flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='dashboard'))
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.shopping_lists.update_one(
                                {'_id': ObjectId(list_id)},
                                {'$set': {'status': 'saved', 'updated_at': datetime.utcnow()}},
                                session=mongo_session
                            )
                    logger.info(f"Saved shopping list {list_id} for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_saved', default='Shopping list saved successfully!'), 'success')
                except Exception as e:
                    logger.error(f"Error saving list {list_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_list_error', default='Error saving shopping list.'), 'danger')
                return redirect(url_for('personal.shopping.main', tab='dashboard'))

            elif action == 'save_list_changes':
                list_id = request.form.get('list_id')
                if not ObjectId.is_valid(list_id):
                    flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='manage-list'))
                shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                if not shopping_list:
                    flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='manage-list'))
                new_name = request.form.get('list_name', shopping_list['name'])
                new_budget_str = request.form.get('list_budget', str(shopping_list['budget']))
                try:
                    new_budget = float(clean_currency(new_budget_str))
                    if new_budget < 0 or new_budget > 10000000000:
                        raise ValueError
                except ValueError:
                    flash(trans('shopping_budget_invalid', default='Invalid budget value.'), 'danger')
                    return redirect(url_for('personal.shopping.main', tab='manage-list'))
                existing_items = list(db.shopping_items.find({'list_id': list_id}))
                added = 0
                edited = 0
                deleted = 0
                last_deleted = session.get('last_deleted_item', None)
                if last_deleted:
                    del session['last_deleted_item']
                for item in existing_items:
                    item_id = str(item['_id'])
                    if f'delete_{item_id}' in request.form:
                        db.shopping_items.delete_one({'_id': item['_id']})
                        session['last_deleted_item'] = {
                            'item': item,
                            'deleted_at': datetime.utcnow().isoformat()
                        }
                        deleted += 1
                    else:
                        new_item_data = {
                            'name': request.form.get(f'item_{item_id}_name', item['name']),
                            'quantity': int(request.form.get(f'item_{item_id}_quantity', item['quantity'])),
                            'price': float(clean_currency(request.form.get(f'item_{item_id}_price', str(item['price'])))),
                            'unit': request.form.get(f'item_{item_id}_unit', item.get('unit', 'piece')),
                            'category': request.form.get(f'item_{item_id}_category', item['category']),
                            'status': request.form.get(f'item_{item_id}_status', item['status']),
                            'store': request.form.get(f'item_{item_id}_store', item['store']),
                            'frequency': int(request.form.get(f'item_{item_id}_frequency', item['frequency'])),
                        }
                        if any(new_item_data[key] != item[key] for key in new_item_data):
                            db.shopping_items.update_one(
                                {'_id': item['_id']},
                                {'$set': {**new_item_data, 'updated_at': datetime.utcnow()}}
                            )
                            edited += 1
                for i in range(1, 6):  # 5 new item slots
                    new_name = request.form.get(f'new_item_name_{i}', '').strip()
                    if new_name:
                        try:
                            new_quantity = int(request.form.get(f'new_item_quantity_{i}', 1))
                            new_price_str = request.form.get(f'new_item_price_{i}', '0')
                            new_price = float(clean_currency(new_price_str))
                            new_unit = request.form.get(f'new_item_unit_{i}', 'piece')
                            new_category = request.form.get(f'new_item_category_{i}', 'other')
                            new_status = request.form.get(f'new_item_status_{i}', 'to_buy')
                            new_store = request.form.get(f'new_item_store_{i}', 'Unknown')
                            new_frequency = int(request.form.get(f'new_item_frequency_{i}', 7))
                            if new_quantity < 1 or new_quantity > 1000 or new_price < 0 or new_price > 1000000 or new_frequency < 1 or new_frequency > 365:
                                raise ValueError('Invalid input range')
                            new_item_data = {
                                '_id': ObjectId(),
                                'list_id': list_id,
                                'user_id': str(current_user.id) if current_user.is_authenticated else None,
                                'session_id': session['sid'],
                                'name': new_name,
                                'quantity': new_quantity,
                                'price': new_price,
                                'unit': new_unit,
                                'category': new_category,
                                'status': new_status,
                                'store': new_store,
                                'frequency': new_frequency,
                                'created_at': datetime.utcnow(),
                                'updated_at': datetime.utcnow()
                            }
                            db.shopping_items.insert_one(new_item_data)
                            added += 1
                        except ValueError as e:
                            flash(trans('shopping_item_error', default='Error adding new item: ') + str(e), 'danger')
                total_operations = added + edited + deleted
                required_credits = total_operations * 0.1
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=required_credits, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for saving changes to list {list_id} by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to save changes. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                db.shopping_lists.update_one(
                    {'_id': ObjectId(list_id)},
                    {'$set': {'name': new_name, 'budget': new_budget, 'updated_at': datetime.utcnow()}}
                )
                items = list(db.shopping_items.find({'list_id': list_id}))
                total_spent = sum(item['price'] * item['quantity'] for item in items)
                db.shopping_lists.update_one(
                    {'_id': ObjectId(list_id)},
                    {'$set': {'total_spent': total_spent}}
                )
                if current_user.is_authenticated and not is_admin():
                    if not deduct_ficore_credits(db, current_user.id, required_credits, 'save_shopping_list_changes', list_id):
                        flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for saving changes.'), 'danger')
                    else:
                        flash(trans('shopping_changes_saved', default='Changes saved successfully!'), 'success')
                if total_spent > new_budget:
                    over_by = total_spent - new_budget
                    flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(over_by) + '.', 'warning')
                return redirect(url_for('personal.shopping.main', tab='manage-list'))

            elif action == 'undo_last_delete':
                last_deleted = session.get('last_deleted_item')
                if last_deleted and ObjectId.is_valid(last_deleted['item']['_id']):
                    try:
                        deleted_at = datetime.fromisoformat(last_deleted['deleted_at'])
                        if (datetime.utcnow() - deleted_at).total_seconds() > 120:  # 2-minute timeout
                            del session['last_deleted_item']
                            flash(trans('shopping_undo_expired', default='Undo period has expired.'), 'warning')
                            return redirect(url_for('personal.shopping.main', tab='manage-list'))
                    except (ValueError, TypeError):
                        del session['last_deleted_item']
                        flash(trans('shopping_no_undo', default='No recent deletion to undo.'), 'warning')
                        return redirect(url_for('personal.shopping.main', tab='manage-list'))
                    list_id = last_deleted['item']['list_id']
                    shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
                    if shopping_list:
                        db.shopping_items.insert_one(last_deleted['item'])
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(list_id)},
                            {'$inc': {'total_spent': last_deleted['item']['price'] * last_deleted['item']['quantity']}, '$set': {'updated_at': datetime.utcnow()}}
                        )
                        del session['last_deleted_item']
                        flash(trans('shopping_item_restored', default='Last deleted item restored!'), 'success')
                    else:
                        flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
                else:
                    flash(trans('shopping_no_undo', default='No recent deletion to undo.'), 'warning')
                return redirect(url_for('personal.shopping.main', tab='manage-list'))

        lists = list(db.shopping_lists.find(filter_criteria).sort('created_at', -1).limit(10))
        lists_dict = {}
        for lst in lists:
            list_items = list(db.shopping_items.find({'list_id': str(lst['_id'])}))
            list_data = {
                'id': str(lst['_id']),
                'name': lst.get('name'),
                'budget': format_currency(lst.get('budget', 0.0)),
                'budget_raw': float(lst.get('budget', 0.0)),
                'total_spent': format_currency(lst.get('total_spent', 0.0)),
                'total_spent_raw': float(lst.get('total_spent', 0.0)),
                'status': lst.get('status', 'active'),
                'created_at': lst.get('created_at').strftime('%Y-%m-%d') if lst.get('created_at') else 'N/A',
                'collaborators': lst.get('collaborators', []),
                'items': [{
                    'id': str(item['_id']),
                    'name': item.get('name'),
                    'quantity': item.get('quantity', 1),
                    'price': format_currency(item.get('price', 0.0)),
                    'price_raw': float(item.get('price', 0.0)),
                    'unit': item.get('unit', 'piece'),
                    'category': item.get('category', 'other'),
                    'status': item.get('status', 'to_buy'),
                    'store': item.get('store', 'Unknown'),
                    'frequency': item.get('frequency', 7)
                } for item in list_items]
            }
            lists_dict[list_data['id']] = list_data
            if not latest_list or (lst.get('created_at') and (latest_list['created_at'] == 'N/A' or lst.get('created_at') > datetime.strptime(latest_list['created_at'], '%Y-%m-%d'))):
                latest_list = list_data
                items = list_data['items']
                categories = {
                    trans('shopping_category_fruits', default='Fruits'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'fruits'),
                    trans('shopping_category_vegetables', default='Vegetables'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'vegetables'),
                    trans('shopping_category_dairy', default='Dairy'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'dairy'),
                    trans('shopping_category_meat', default='Meat'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'meat'),
                    trans('shopping_category_grains', default='Grains'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'grains'),
                    trans('shopping_category_beverages', default='Beverages'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'beverages'),
                    trans('shopping_category_household', default='Household'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'household'),
                    trans('shopping_category_other', default='Other'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'other')
                }
                categories = {k: v for k, v in categories.items() if v > 0}

        if not latest_list:
            latest_list = {
                'id': None,
                'name': '',
                'budget': format_currency(0.0),
                'budget_raw': 0.0,
                'total_spent': format_currency(0.0),
                'total_spent_raw': 0.0,
                'status': 'active',
                'created_at': 'N/A',
                'collaborators': [],
                'items': []
            }
            items = []

        tips = [
            trans('shopping_tip_plan_ahead', default='Plan your shopping list ahead to avoid impulse buys.'),
            trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
            trans('shopping_tip_bulk_buy', default='Buy non-perishable items in bulk to reduce costs.'),
            trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
        ]
        insights = []
        if latest_list['budget_raw'] > 0:
            if latest_list['total_spent_raw'] > latest_list['budget_raw']:
                insights.append(trans('shopping_insight_over_budget', default='You are over budget. Consider removing non-essential items.'))
            elif latest_list['total_spent_raw'] < latest_list['budget_raw'] * 0.5:
                insights.append(trans('shopping_insight_under_budget', default='You are under budget. Consider allocating funds to savings.'))

        return render_template(
            'personal/SHOPPING/shopping_main.html',
            list_form=list_form,
            item_form=item_form,
            share_form=share_form,
            edit_form=edit_form,
            lists=lists_dict,
            latest_list=latest_list,
            items=items,
            categories=categories,
            tips=tips,
            insights=insights,
            tool_title=trans('shopping_title', default='Shopping List Planner'),
            active_tab=active_tab
        )
    except Exception as e:
        logger.error(f"Unexpected error in shopping.main: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        flash(trans('shopping_dashboard_load_error', default='Error loading shopping dashboard.'), 'danger')
        return render_template(
            'personal/SHOPPING/shopping_main.html',
            list_form=list_form,
            item_form=item_form,
            share_form=share_form,
            edit_form=edit_form,
            lists={},
            latest_list={
                'id': None,
                'name': '',
                'budget': format_currency(0.0),
                'budget_raw': 0.0,
                'total_spent': format_currency(0.0),
                'total_spent_raw': 0.0,
                'status': 'active',
                'created_at': 'N/A',
                'collaborators': [],
                'items': []
            },
            items=[],
            categories={},
            tips=[],
            insights=[],
            tool_title=trans('shopping_title', default='Shopping List Planner'),
            active_tab=active_tab
        ), 500

@shopping_bp.route('/lists/<list_id>/edit', methods=['GET', 'POST'])
@login_required
@requires_role(['personal', 'admin'])
def edit_list(list_id):
    db = get_mongo_db()
    edit_form = ShoppingListEditForm()
    filter_criteria = {'user_id': str(current_user.id)} if not is_admin() else {}
    
    try:
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
        if not shopping_list:
            flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
            return redirect(url_for('personal.shopping.main', tab='manage-list'))
        
        if request.method == 'POST' and edit_form.validate_on_submit():
            if current_user.is_authenticated and not is_admin():
                if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                    logger.warning(f"Insufficient Ficore Credits for editing list {list_id} by user {current_user.id}", 
                                  extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to edit a list. Please purchase more credits.'), 'danger')
                    return redirect(url_for('agents_bp.manage_credits'))
            
            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        db.shopping_lists.update_one(
                            {'_id': ObjectId(list_id)},
                            {
                                '$set': {
                                    'name': edit_form.name.data,
                                    'budget': edit_form.budget.data,
                                    'updated_at': datetime.utcnow()
                                }
                            },
                            session=mongo_session
                        )
                        if current_user.is_authenticated and not is_admin():
                            if not deduct_ficore_credits(db, current_user.id, 0.1, 'edit_shopping_list', list_id, mongo_session):
                                logger.error(f"Failed to deduct 0.1 Ficore Credits for editing list {list_id} by user {current_user.id}", 
                                             extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for editing list.'), 'danger')
                                return redirect(url_for('personal.shopping.main', tab='manage-list'))
                logger.info(f"Updated shopping list {list_id} for user {current_user.id}", 
                            extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                flash(trans('shopping_list_updated', default='Shopping list updated successfully!'), 'success')
                return redirect(url_for('personal.shopping.main', tab='manage-list'))
            except Exception as e:
                logger.error(f"Error updating list {list_id}: {str(e)}", 
                             extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                flash(trans('shopping_list_error', default='Error updating shopping list.'), 'danger')
        
        edit_form.name.data = shopping_list.get('name')
        edit_form.budget.data = float(shopping_list.get('budget', 0.0))
        
        return render_template(
            'personal/SHOPPING/shopping_main.html',
            list_form=ShoppingListForm(),
            item_form=ShoppingItemForm(),
            share_form=ShareListForm(),
            edit_form=edit_form,
            lists={str(shopping_list['_id']): {
                'id': str(shopping_list['_id']),
                'name': shopping_list.get('name'),
                'budget': format_currency(shopping_list.get('budget', 0.0)),
                'budget_raw': float(shopping_list.get('budget', 0.0)),
                'total_spent': format_currency(shopping_list.get('total_spent', 0.0)),
                'total_spent_raw': float(shopping_list.get('total_spent', 0.0)),
                'status': shopping_list.get('status', 'active'),
                'created_at': shopping_list.get('created_at').strftime('%Y-%m-%d') if shopping_list.get('created_at') else 'N/A',
                'collaborators': shopping_list.get('collaborators', []),
                'items': [{
                    'id': str(item['_id']),
                    'name': item.get('name'),
                    'quantity': item.get('quantity', 1),
                    'price': format_currency(item.get('price', 0.0)),
                    'price_raw': float(item.get('price', 0.0)),
                    'unit': item.get('unit', 'piece'),
                    'category': item.get('category', 'other'),
                    'status': item.get('status', 'to_buy'),
                    'store': item.get('store', 'Unknown'),
                    'frequency': item.get('frequency', 7)
                } for item in db.shopping_items.find({'list_id': str(shopping_list['_id'])})]
            }},
            latest_list=None,
            items=[],
            categories={},
            tips=[],
            insights=[],
            tool_title=trans('shopping_title', default='Shopping List Planner'),
            active_tab='manage-list'
        )
    except Exception as e:
        logger.error(f"Error in edit_list for list {list_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        flash(trans('shopping_list_error', default='Error loading shopping list for editing.'), 'danger')
        return redirect(url_for('personal.shopping.main', tab='manage-list'))

@shopping_bp.route('/lists/<list_id>/export_pdf', methods=['GET'])
@login_required
@requires_role(['personal', 'admin'])
def export_list_pdf(list_id):
    db = get_mongo_db()
    try:
        if not ObjectId.is_valid(list_id):
            logger.error(f"Invalid list_id {list_id}: not a valid ObjectId", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('shopping_invalid_list_id', default='Invalid list ID format.'), 'danger')
            return redirect(url_for('personal.shopping.main', tab='dashboard'))
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), 'user_id': str(current_user.id)})
        if not shopping_list:
            flash(trans('shopping_list_not_found', default='Shopping list not found or you are not the owner.'), 'danger')
            return redirect(url_for('personal.shopping.main', tab='dashboard'))
        if shopping_list.get('status') != 'saved':
            flash(trans('shopping_list_not_saved', default='Shopping list must be saved before exporting to PDF.'), 'danger')
            return redirect(url_for('personal.shopping.main', tab='dashboard'))
        if current_user.is_authenticated and not is_admin():
            if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                logger.warning(f"Insufficient Ficore Credits for exporting list {list_id} to PDF by user {current_user.id}", 
                              extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                flash(trans('shopping_insufficient_credits', default='Insufficient Ficore Credits to export list to PDF. Please purchase more credits.'), 'danger')
                return redirect(url_for('agents_bp.manage_credits'))
        try:
            log_tool_usage(
                tool_name='shopping',
                db=db,
                user_id=current_user.id if current_user.is_authenticated else None,
                session_id=session.get('sid', 'no-session-id'),
                action='export_shopping_list_pdf'
            )
        except Exception as e:
            logger.error(f"Failed to log PDF export: {str(e)}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('shopping_log_error', default='Error logging PDF export. Continuing with export.'), 'warning')
        items = db.shopping_items.find({'list_id': list_id}).sort('created_at', -1)
        shopping_data = {
            'lists': [{
                'name': shopping_list.get('name'),
                'budget': float(shopping_list.get('budget', 0)),
                'total_spent': float(shopping_list.get('total_spent', 0)),
                'collaborators': shopping_list.get('collaborators', []),
                'created_at': shopping_list.get('created_at')
            }],
            'items': [{
                'name': i.get('name'),
                'quantity': i.get('quantity', 1),
                'price': float(i.get('price', 0)),
                'unit': i.get('unit', 'piece'),
                'category': i.get('category', 'other'),
                'status': i.get('status', 'to_buy'),
                'store': i.get('store', 'Unknown'),
                'created_at': i.get('created_at')
            } for i in items]
        }
        with db.client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                buffer = BytesIO()
                p = canvas.Canvas(buffer, pagesize=A4)
                header_height = 0.7
                extra_space = 0.2
                row_height = 0.3
                bottom_margin = 0.5
                max_y = 10.5
                title_y = max_y - header_height - extra_space
                page_height = (max_y - bottom_margin) * inch
                rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))
                total_budget = float(shopping_data['lists'][0]['budget'])
                total_spent = float(shopping_data['lists'][0]['total_spent'])
                total_price = sum(float(item['price']) * item['quantity'] for item in shopping_data['items'])
                def draw_list_headers(y):
                    p.setFillColor(colors.black)
                    p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
                    p.drawString(2 * inch, y * inch, trans('general_list_name', default='List Name'))
                    p.drawString(3.5 * inch, y * inch, trans('general_budget', default='Budget'))
                    p.drawString(4.5 * inch, y * inch, trans('general_total_spent', default='Total Spent'))
                    p.drawString(5.5 * inch, y * inch, trans('general_collaborators', default='Collaborators'))
                    return y - row_height
                def draw_item_headers(y):
                    p.setFillColor(colors.black)
                    p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
                    p.drawString(2 * inch, y * inch, trans('general_item_name', default='Item Name'))
                    p.drawString(3 * inch, y * inch, trans('general_quantity', default='Quantity'))
                    p.drawString(3.8 * inch, y * inch, trans('general_price', default='Price'))
                    p.drawString(4.5 * inch, y * inch, trans('general_unit', default='Unit'))
                    p.drawString(5.2 * inch, y * inch, trans('general_status', default='Status'))
                    p.drawString(5.9 * inch, y * inch, trans('general_category', default='Category'))
                    p.drawString(6.6 * inch, y * inch, trans('general_store', default='Store'))
                    return y - row_height
                draw_ficore_pdf_header(p, current_user, y_start=max_y)
                p.setFont("Helvetica", 12)
                p.drawString(1 * inch, title_y * inch, trans('shopping_list_report', default='Shopping List Report'))
                p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
                y = title_y - 0.6
                p.setFont("Helvetica", 10)
                y = draw_list_headers(y)
                row_count = 0
                list_data = shopping_data['lists'][0]
                p.drawString(1 * inch, y * inch, format_date(list_data['created_at']))
                p.drawString(2 * inch, y * inch, list_data['name'])
                p.drawString(3.5 * inch, y * inch, format_currency(list_data['budget']))
                p.drawString(4.5 * inch, y * inch, format_currency(list_data['total_spent']))
                p.drawString(5.5 * inch, y * inch, ', '.join(list_data['collaborators']) or 'None')
                y -= row_height
                row_count += 1
                y -= 0.5
                p.drawString(1 * inch, y * inch, trans('shopping_items', default='Items'))
                y -= row_height
                y = draw_item_headers(y)
                for item in shopping_data['items']:
                    if row_count + 1 >= rows_per_page:
                        p.showPage()
                        draw_ficore_pdf_header(p, current_user, y_start=max_y)
                        y = title_y - 0.6
                        y = draw_item_headers(y)
                        row_count = 0
                    p.drawString(1 * inch, y * inch, format_date(item['created_at']))
                    p.drawString(2 * inch, y * inch, item['name'][:20])
                    p.drawString(3 * inch, y * inch, str(item['quantity']))
                    p.drawString(3.8 * inch, y * inch, format_currency(item['price']))
                    p.drawString(4.5 * inch, y * inch, trans(item['unit'], default=item['unit']))
                    p.drawString(5.2 * inch, y * inch, trans(item['status'], default=item['status']))
                    p.drawString(5.9 * inch, y * inch, trans(item['category'], default=item['category']))
                    p.drawString(6.6 * inch, y * inch, item['store'][:15])
                    y -= row_height
                    row_count += 1
                if row_count + 3 <= rows_per_page:
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_budget', default='Total Budget')}: {format_currency(total_budget)}")
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_spent', default='Total Spent')}: {format_currency(total_spent)}")
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_price', default='Total Price')}: {format_currency(total_price)}")
                else:
                    p.showPage()
                    draw_ficore_pdf_header(p, current_user, y_start=max_y)
                    y = title_y - 0.6
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_budget', default='Total Budget')}: {format_currency(total_budget)}")
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_spent', default='Total Spent')}: {format_currency(total_spent)}")
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('reports_total_price', default='Total Price')}: {format_currency(total_price)}")
                p.save()
                buffer.seek(0)
                if current_user.is_authenticated and not is_admin():
                    if not deduct_ficore_credits(db, current_user.id, 0.1, 'export_shopping_list_pdf', list_id, mongo_session):
                        logger.error(f"Failed to deduct 0.1 Ficore Credits for exporting list {list_id} to PDF by user {current_user.id}", 
                                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('shopping_credit_deduction_failed', default='Failed to deduct Ficore Credits for exporting list to PDF.'), 'danger')
                        return redirect(url_for('personal.shopping.main', tab='dashboard'))
        logger.info(f"Exported shopping list {list_id} to PDF for user {current_user.id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=shopping_list_{list_id}.pdf'})
    except Exception as e:
        logger.error(f"Error exporting list {list_id} to PDF: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        flash(trans('shopping_export_error', default='Error exporting shopping list to PDF.'), 'danger')
        return redirect(url_for('personal.shopping.main', tab='dashboard'))

def process_delayed_deletion(list_id, user_id, session_id):
    with app.app_context():
        db = get_mongo_db()
        try:
            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    pending = db.pending_deletions.find_one({'list_id': list_id, 'user_id': str(user_id) if user_id else None}, session=mongo_session)
                    if not pending:
                        logger.info(f"No pending deletion found for list {list_id}", 
                                    extra={'session_id': session_id, 'ip_address': 'unknown'})
                        return
                    shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), 'user_id': str(user_id) if user_id else None}, session=mongo_session)
                    if not shopping_list:
                        db.pending_deletions.delete_one({'list_id': list_id}, session=mongo_session)
                        logger.info(f"No shopping list found for {list_id}, removed pending deletion", 
                                    extra={'session_id': session_id, 'ip_address': 'unknown'})
                        return
                    db.shopping_items.delete_many({'list_id': list_id}, session=mongo_session)
                    result = db.shopping_lists.delete_one({'_id': ObjectId(list_id)}, session=mongo_session)
                    if result.deleted_count == 0:
                        logger.error(f"Failed to delete shopping list {list_id}: No documents deleted", 
                                     extra={'session_id': session_id, 'ip_address': 'unknown'})
                        raise ValueError(f"Failed to delete shopping list {list_id}")
                    db.pending_deletions.delete_one({'list_id': list_id}, session=mongo_session)
            logger.info(f"Completed delayed deletion of shopping list {list_id}", 
                        extra={'session_id': session_id, 'ip_address': 'unknown'})
        except Exception as e:
            logger.error(f"Error in delayed deletion of list {list_id}: {str(e)}", 
                         extra={'session_id': session_id, 'ip_address': 'unknown'})

@shopping_bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF error on {request.path}: {e.description}", 
                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
    flash(trans('shopping_csrf_error', default='Form submission failed due to a missing security token. Please refresh and try again.'), 'danger')
    return redirect(url_for('personal.shopping.main', tab='create-list')), 403

def init_app(app):
    try:
        db = get_mongo_db()
        db.shopping_lists.create_index([('user_id', 1), ('status', 1), ('updated_at', -1)])
        db.shopping_items.create_index([('list_id', 1), ('created_at', -1)])
        db.pending_deletions.create_index([('list_id', 1), ('user_id', 1)])
        app.register_blueprint(shopping_bp)
        logger.info("Initialized shopping blueprint", extra={'session_id': 'no-request-context'})
    except Exception as e:
        logger.error(f"Error initializing shopping blueprint: {str(e)}", 
                     extra={'session_id': 'no-request-context', 'stack_trace': traceback.format_exc()})
        raise
