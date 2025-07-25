from flask import Blueprint, request, redirect, url_for, render_template, flash, jsonify, Response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, FloatField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Email
from flask_login import current_user, login_required
from datetime import datetime
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
import uuid
from models import log_tool_usage, create_shopping_list, get_shopping_lists, update_shopping_list, delete_shopping_list, create_shopping_item, get_shopping_items, update_shopping_item, to_dict_shopping_list, to_dict_shopping_item

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

def deduct_ficore_credits(db, user_id, email, amount, action, item_id=None, mongo_session=None):
    try:
        if amount <= 0:
            logger.error(f"Invalid deduction amount {amount} for user {user_id}, email: {email}, action: {action}")
            return False
        user = db.users.find_one({'_id': user_id, 'email': email.lower()}, session=mongo_session)
        if not user:
            logger.error(f"User {user_id}, email: {email} not found for credit deduction, action: {action}")
            return False
        current_balance = user.get('ficore_credit_balance', 0)
        if current_balance < amount:
            logger.warning(f"Insufficient credits for user {user_id}, email: {email}: required {amount}, available {current_balance}, action: {action}")
            return False
        session_to_use = mongo_session if mongo_session else db.client.start_session()
        owns_session = not mongo_session
        try:
            with session_to_use.start_transaction() if not mongo_session else nullcontext():
                result = db.users.update_one(
                    {'_id': user_id, 'email': email.lower()},
                    {'$inc': {'ficore_credit_balance': -amount}},
                    session=session_to_use
                )
                if result.modified_count == 0:
                    logger.error(f"Failed to deduct {amount} credits for user {user_id}, email: {email}, action: {action}: No documents modified")
                    raise ValueError(f"Failed to update user balance for {user_id}, email: {email}")
                transaction = {
                    '_id': ObjectId(),
                    'user_id': user_id,
                    'email': email.lower(),
                    'amount': -amount,
                    'type': action,
                    'ref': str(item_id) if item_id else None,
                    'date': datetime.utcnow(),
                    'status': 'completed'
                }
                db.ficore_credit_transactions.insert_one(transaction, session=session_to_use)
            logger.info(f"Deducted {amount} Ficore Credits for {action} by user {user_id}, email: {email}")
            return True
        except (ValueError, errors.PyMongoError) as e:
            logger.error(f"Transaction aborted for user {user_id}, email: {email}, action: {action}: {str(e)}")
            return False
        finally:
            if owns_session:
                session_to_use.end_session()
    except Exception as e:
        logger.error(f"Unexpected error deducting {amount} Ficore Credits for {action} by user {user_id}, email: {email}: {str(e)}")
        return False

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
        lang = request.args.get('lang', 'en')
        self.name.label.text = trans('shopping_list_name', lang) or 'List Name'
        self.budget.label.text = trans('shopping_budget', lang) or 'Budget'
        self.submit.label.text = trans('shopping_submit', lang) or 'Create List'

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
        lang = request.args.get('lang', 'en')
        self.name.label.text = trans('shopping_item_name', lang) or 'Item Name'
        self.quantity.label.text = trans('shopping_quantity', lang) or 'Quantity'
        self.price.label.text = trans('shopping_price', lang) or 'Price'
        self.unit.label.text = trans('shopping_unit', lang) or 'Unit'
        self.store.label.text = trans('shopping_store', lang) or 'Store'
        self.category.label.text = trans('shopping_category', lang) or 'Category'
        self.status.label.text = trans('shopping_status', default='Status')
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
        lang = request.args.get('lang', 'en')
        self.email.label.text = trans('shopping_collaborator_email', lang) or 'Collaborator Email'
        self.submit.label.text = trans('shopping_share_submit', lang) or 'Share List'

@shopping_bp.route('/', methods=['GET'])
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('shopping.main'))
    return render_template('general/landingpage.html', tool_title=trans('shopping_title', default='Shopping List Planner'))

@shopping_bp.route('/main', methods=['GET', 'POST'])
@login_required
@requires_role(['personal', 'admin'])
def main():
    list_form = ShoppingListForm()
    item_form = ShoppingItemForm()
    share_form = ShareListForm()
    db = get_mongo_db()

    valid_tabs = ['create-list', 'dashboard', 'manage-list']
    active_tab = request.args.get('tab', 'create-list')
    if active_tab not in valid_tabs:
        active_tab = 'create-list'

    filter_criteria = {'user_id': str(current_user.id), 'email': current_user.email.lower()} if not is_admin() else {}
    lists = []
    selected_list = None
    categories = {}
    items = []

    try:
        log_tool_usage(
            tool_name='shopping',
            db=db,
            user_id=current_user.id,
            email=current_user.email,
            action='main_view'
        )
    except Exception as e:
        flash(trans('shopping_log_error', default='Error logging activity.'), 'danger')

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_list' and list_form.validate_on_submit():
            if not is_admin():
                if not check_ficore_credit_balance(db, required_amount=0.1, user_id=current_user.id, email=current_user.email):
                    flash(trans('shopping_insufficient_credits', default='Insufficient credits to create a list.'), 'danger')
                    return redirect(url_for('dashboard.index'))
            list_data = {
                'user_id': str(current_user.id),
                'email': current_user.email.lower(),
                'name': list_form.name.data,
                'budget': float(list_form.budget.data),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'collaborators': [],
                'total_spent': 0.0,
                'status': 'ongoing'
            }
            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        list_id = create_shopping_list(db, list_data)
                        if not is_admin():
                            if not deduct_ficore_credits(db, current_user.id, current_user.email, 0.001, 'create_shopping_list', list_id, mongo_session):
                                delete_shopping_list(db, list_id, current_user.id, current_user.email)
                                flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits.'), 'danger')
                                return redirect(url_for('shopping.main', tab='create-list'))
                flash(trans('shopping_list_created', default='Shopping list created successfully!'), 'success')
                return redirect(url_for('shopping.main', tab='dashboard'))
            except Exception as e:
                logger.error(f"Failed to create list: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
                flash(trans('shopping_list_error', default='Error creating shopping list.'), 'danger')

        elif action == 'save_list':
            list_id = request.form.get('list_id')
            if not ObjectId.is_valid(list_id):
                flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            shopping_list = db.shopping_lists.find_one({'_id': {ObjectId(list_id)}, **filter_criteria})
            if not shopping_list:
                flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            items_data = request.form.get('items_data', '[]')
            try:
                import json
                items = json.loads(items_data)
                total_operations = len(items)
                required_credits = total_operations * 0.1
                if not is_admin():
                    if not check_ficore_credit_balance(db, required_amount=required_credits, user_id=current_user.id, email=current_user.email):
                        flash(trans('shopping_insufficient_credits', default='Insufficient credits to save items.'), 'danger')
                        return redirect(url_for('dashboard.index'))
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        total_spent = 0.0
                        for item in items:
                            item_id = str(ObjectId())
                            item_data = {
                                'user_id': str(current_user.id),
                                'email': current_user.email.lower(),
                                'list_id': list_id,
                                'name': item['name'],
                                'quantity': int(item['quantity']),
                                'price': float(clean_currency(item['price'])),
                                'unit': item['unit'],
                                'category': item['category'],
                                'status': item['status'],
                                'store': item['store'],
                                'frequency': int(item['frequency']),
                                'created_at': datetime.utcnow(),
                                'updated_at': datetime.utcnow()
                            }
                            create_shopping_item(db, item_data)
                            total_spent += item_data['price'] * item_data['quantity']
                            if not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, current_user.email, 0.1, 'add_shopping_item', item_id, mongo_session):
                                    flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits for item.'), 'danger')
                                    return redirect(url_for('shopping.main', tab='dashboard'))
                        update_shopping_list(db, list_id, current_user.id, current_user.email, {
                            'status': 'saved',
                            'total_spent': total_spent,
                            'updated_at': datetime.utcnow()
                        })
                flash(trans('shopping_list_saved', default='Shopping list saved successfully!'), 'success')
                if total_spent > shopping_list['budget']:
                    flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(total_spent - shopping_list['budget']) + '.', 'warning')
                return redirect(url_for('shopping.main', tab='dashboard'))
            except Exception as e:
                logger.error(f"Error saving list {list_id}: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
                flash(trans('shopping_list_error', default='Error saving shopping list.'), 'danger')

        elif action == 'share_list' and share_form.validate_on_submit():
            list_id = request.form.get('list_id')
            if not ObjectId.is_valid(list_id):
                flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
            if not shopping_list:
                flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            collaborator = db.users.find_one({'email': share_form.email.data.lower()})
            if not collaborator:
                flash(trans('shopping_user_not_found', default='User with this email not found.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            try:
                update_shopping_list(db, list_id, current_user.id, current_user.email, {
                    'collaborators': shopping_list.get('collaborators', []) + [share_form.email.data.lower()],
                    'updated_at': datetime.utcnow()
                })
                flash(trans('shopping_list_shared', default='Shopping list shared successfully!'), 'success')
            except Exception as e:
                logger.error(f"Error sharing list {list_id}: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
                flash(trans('shopping_share_error', default='Error sharing shopping list.'), 'danger')
            return redirect(url_for('shopping.main', tab='dashboard'))

        elif action == 'delete_list':
            list_id = request.form.get('list_id')
            if not ObjectId.is_valid(list_id):
                flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
            if not shopping_list:
                flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
                return redirect(url_for('shopping.main', tab='dashboard'))
            if not is_admin():
                if not check_ficore_credit_balance(db, required_amount=0.5, user_id=current_user.id, email=current_user.email):
                    flash(trans('shopping_insufficient_credits', default='Insufficient credits to delete list.'), 'danger')
                    return redirect(url_for('dashboard.index'))
            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        delete_shopping_list(db, list_id, current_user.id, current_user.email)
                        if not is_admin():
                            if not deduct_ficore_credits(db, current_user.id, current_user.email, 0.5, 'delete_shopping_list', list_id, mongo_session):
                                flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits for deletion.'), 'danger')
                                return redirect(url_for('shopping.main', tab='dashboard'))
                flash(trans('shopping_list_deleted', default='Shopping list deleted successfully!'), 'success')
            except Exception as e:
                logger.error(f"Error deleting list {list_id}: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
                flash(trans('shopping_list_error', default='Error deleting shopping list.'), 'danger')
            return redirect(url_for('shopping.main', tab='dashboard'))

    lists = get_shopping_lists(db, current_user.id, current_user.email, status='active')
    lists_dict = {to_dict_shopping_list(lst)['id']: to_dict_shopping_list(lst) for lst in lists}

    selected_list_id = request.args.get('list_id')
    if selected_list_id and ObjectId.is_valid(selected_list_id):
        selected_list = lists_dict.get(selected_list_id)
        if selected_list:
            items = get_shopping_items(db, {'list_id': selected_list_id, 'user_id': current_user.id, 'email': current_user.email.lower()})
            items = [to_dict_shopping_item(item) for item in items]
            categories = {
                trans('shopping_category_fruits', default='Fruits'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'fruits'),
                trans('shopping_category_vegetables', default='Vegetables'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'vegetables'),
                trans('shopping_category_dairy', default='Dairy'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'dairy'),
                trans('shopping_category_meat', default='Meat'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'meat'),
                trans('shopping_category_grains', default='Grains'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'grains'),
                trans('shopping_category_beverages', default='Beverages'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'beverages'),
                trans('shopping_category_household', default='Household'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'household'),
                trans('shopping_category_other', default='Other'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'other')
            }
            categories = {k: format_currency(v) for k, v in categories.items() if v > 0}

    tips = [
        trans('shopping_tip_plan_ahead', default='Plan your shopping list ahead to avoid impulse buys.'),
        trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
        trans('shopping_tip_bulk_buy', default='Buy non-perishable items in bulk to reduce costs.'),
        trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
    ]
    insights = []
    if selected_list and selected_list['budget'] > 0:
        if selected_list['total_spent'] > selected_list['budget']:
            insights.append(trans('shopping_insight_over_budget', default='You are over budget. Consider removing non-essential items.'))
        elif selected_list['total_spent'] < selected_list['budget'] * 0.5:
            insights.append(trans('shopping_insight_under_budget', default='You are under budget. Consider allocating funds to savings.'))

    return render_template(
        'personal/SHOPPING/shopping_main.html',
        list_form=list_form,
        item_form=item_form,
        share_form=share_form,
        lists=lists_dict,
        selected_list=selected_list,
        items=items,
        categories=categories,
        tips=tips,
        insights=insights,
        tool_title=trans('shopping_title', default='Shopping List Planner'),
        active_tab=active_tab
    )

@shopping_bp.route('/lists/<list_id>/manage', methods=['GET', 'POST'])
@login_required
@requires_role(['personal', 'admin'])
def manage_list(list_id):
    db = get_mongo_db()
    filter_criteria = {'user_id': str(current_user.id), 'email': current_user.email.lower()} if not is_admin() else {}
    try:
        if not ObjectId.is_valid(list_id):
            flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
            return redirect(url_for('shopping.main', tab='manage-list'))
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), **filter_criteria})
        if not shopping_list:
            flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
            return redirect(url_for('shopping.main', tab='manage-list'))

        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'save_changes':
                new_name = request.form.get('list_name', shopping_list['name'])
                new_budget_str = request.form.get('list_budget', str(shopping_list['budget']))
                try:
                    new_budget = float(clean_currency(new_budget_str))
                    if new_budget < 0 or new_budget > 10000000000:
                        raise ValueError
                except ValueError:
                    flash(trans('shopping_budget_invalid', default='Invalid budget value.'), 'danger')
                    return redirect(url_for('shopping.main', tab='manage-list', list_id=list_id))
                existing_items = get_shopping_items(db, {'list_id': list_id, 'user_id': current_user.id, 'email': current_user.email.lower()})
                added = 0
                edited = 0
                deleted = 0
                for item in existing_items:
                    item_id = item['_id']
                    if f'delete_{item_id}' in request.form:
                        db.shopping_items.delete_one({'_id': ObjectId(item_id), 'user_id': current_user.id, 'email': current_user.email.lower()})
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
                            update_shopping_item(db, item_id, current_user.id, current_user.email, new_item_data)
                            edited += 1
                for i in range(1, 6):
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
                                'user_id': str(current_user.id),
                                'email': current_user.email.lower(),
                                'list_id': list_id,
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
                            create_shopping_item(db, new_item_data)
                            added += 1
                        except ValueError as e:
                            flash(trans('shopping_item_error', default='Error adding new item: ') + str(e), 'danger')
                total_operations = added + edited + deleted
                required_credits = total_operations * 0.1
                if not is_admin():
                    if not check_ficore_credit_balance(db, required_amount=required_credits, user_id=current_user.id, email=current_user.email):
                        flash(trans('shopping_insufficient_credits', default='Insufficient credits to save changes.'), 'danger')
                        return redirect(url_for('dashboard.index'))
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        items = get_shopping_items(db, {'list_id': list_id, 'user_id': current_user.id, 'email': current_user.email.lower()})
                        total_spent = sum(item['price'] * item['quantity'] for item in items)
                        update_shopping_list(db, list_id, current_user.id, current_user.email, {
                            'name': new_name,
                            'budget': new_budget,
                            'total_spent': total_spent,
                            'updated_at': datetime.utcnow()
                        })
                        if not is_admin():
                            if not deduct_ficore_credits(db, current_user.id, current_user.email, required_credits, 'save_shopping_list_changes', list_id, mongo_session):
                                flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits for changes.'), 'danger')
                                return redirect(url_for('shopping.main', tab='manage-list', list_id=list_id))
                flash(trans('shopping_changes_saved', default='Changes saved successfully!'), 'success')
                if total_spent > new_budget:
                    flash(trans('shopping_over_budget', default='Warning: Total spent exceeds budget by ') + format_currency(total_spent - new_budget) + '.', 'warning')
                return redirect(url_for('shopping.main', tab='manage-list', list_id=list_id))

        lists = get_shopping_lists(db, current_user.id, current_user.email, status='active')
        lists_dict = {to_dict_shopping_list(lst)['id']: to_dict_shopping_list(lst) for lst in lists}
        selected_list = lists_dict.get(list_id)
        items = get_shopping_items(db, {'list_id': list_id, 'user_id': current_user.id, 'email': current_user.email.lower()})
        items = [to_dict_shopping_item(item) for item in items]
        categories = {
            trans('shopping_category_fruits', default='Fruits'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'fruits'),
            trans('shopping_category_vegetables', default='Vegetables'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'vegetables'),
            trans('shopping_category_dairy', default='Dairy'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'dairy'),
            trans('shopping_category_meat', default='Meat'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'meat'),
            trans('shopping_category_grains', default='Grains'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'grains'),
            trans('shopping_category_beverages', default='Beverages'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'beverages'),
            trans('shopping_category_household', default='Household'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'household'),
            trans('shopping_category_other', default='Other'): sum(item['price'] * item['quantity'] for item in items if item['category'] == 'other')
        }
        categories = {k: format_currency(v) for k, v in categories.items() if v > 0}

        tips = [
            trans('shopping_tip_plan_ahead', default='Plan your shopping ahead to avoid impulse buys.'),
            trans('shopping_tip_compare_prices', default='Compare prices across stores to save money.'),
            trans('shopping_tip_bulk_buy', default='Buy non-perishables in bulk to reduce costs.'),
            trans('shopping_tip_check_sales', default='Check for sales or discounts before shopping.')
        ]
        insights = []
        if selected_list and selected_list['budget'] > 0:
            if selected_list['total_spent'] > selected_list['budget']:
                insights.append(trans('shopping_insight_over_budget', default='You are over budget. Consider removing non-essential items.'))
            elif selected_list['total_spent'] < selected_list['budget'] * 0.5:
                insights.append(trans('shopping_insight_under_budget', default='You are under budget. Consider allocating funds to savings.'))

        return render_template(
            'personal/SHOPPING/shopping_main.html',
            list_form=ShoppingListForm(),
            item_form=ShoppingItemForm(),
            share_form=ShareListForm(),
            lists=lists_dict,
            selected_list=selected_list,
            items=items,
            categories=categories,
            tips=tips,
            insights=insights,
            tool_title=trans('shopping_title', default='Shopping List Planner'),
            active_tab='manage-list'
        )
    except Exception as e:
        logger.error(f"Error managing list {list_id}: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
        flash(trans('shopping_list_error', default='Error loading shopping list.'), 'danger')
        return redirect(url_for('shopping.main', tab='manage-list'))

@shopping_bp.route('/lists/<list_id>/export_pdf', methods=['GET'])
@login_required
@requires_role(['personal', 'admin'])
def export_list_pdf(list_id):
    db = get_mongo_db()
    try:
        if not ObjectId.is_valid(list_id):
            flash(trans('shopping_invalid_list_id', default='Invalid list ID.'), 'danger')
            return redirect(url_for('shopping.main', tab='dashboard'))
        shopping_list = db.shopping_lists.find_one({'_id': ObjectId(list_id), 'user_id': str(current_user.id), 'email': current_user.email.lower()})
        if not shopping_list:
            flash(trans('shopping_list_not_found', default='Shopping list not found.'), 'danger')
            return redirect(url_for('shopping.main', tab='dashboard'))
        if shopping_list.get('status') != 'saved':
            flash(trans('shopping_list_not_saved', default='Shopping list must be saved before exporting.'), 'danger')
            return redirect(url_for('shopping.main', tab='dashboard'))
        if not is_admin():
            if not check_ficore_credit_balance(db, required_amount=0.1, user_id=current_user.id, email=current_user.email):
                flash(trans('shopping_insufficient_credits', default='Insufficient credits to export PDF.'), 'danger')
                return redirect(url_for('dashboard.index'))
        items = get_shopping_items(db, {'list_id': str(list_id), 'user_id': current_user.id, 'email': current_user.email.lower()})
        shopping_data = {
            'lists': [{
                'name': shopping_list.get('name'),
                'budget': float(shopping_list.get('budget', 0)),
                'total_spent': float(shopping_list.get('total_spent', 0)),
                'collaborators': shopping_list.get('collaborators', []),
                'created_at': shopping_list.get('created_at')
            }],
            'items': [to_dict_shopping_item(item) for item in items]
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
                    p.drawString(1 * inch, y * inch, f'{trans('reports_total_price', default='Total Price')}: {format_currency(total_price)}")
                p.save()
                buffer.seek(0)
                if not is_admin():
                    if not deduct_ficore_credits(db, current_user.id, current_user.email, 0.1, 'export_shopping_list_pdf', list_id, mongo_session):
                        flash(trans('shopping_credit_deduction_failed', default='Failed to deduct credits for PDF export.'), 'danger')
                        return redirect(url_for('shopping.main', tab='dashboard'))
        return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=shopping_list_{list_id}.pdf'})
    except Exception as e:
        logger.error(f"Error exporting PDF for list {list_id}: {str(e)}", extra={'user_id': current_user.id, 'email': current_user.email})
        flash(trans('shopping_export_error', default='Error exporting to PDF.'), 'danger')
        return redirect(url_for('shopping.main', tab='dashboard'))

@shopping_bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF error on {request.path}: {e.description}", extra={'user_id': current_user.id if current_user.is_authenticated else 'anonymous', 'email': current_user.email if current_user.is_authenticated else 'no-email'})
    flash(trans('shopping_csrf_error', default='Form submission failed. Please refresh and try again.'), 'danger')
    return redirect(url_for('shopping.main', tab='create-list')), 404

def init_app(app):
    try:
        db = get_mongo_db()
        db.shopping_lists.create_index([('user_id', 1), ('email', 1), ('status', 1), ('updated_at', -1)])
        db.shopping_items.create_index([('list_id', 1), ('user_id', 1), ('email', 1), ('created_at', -1)])
        app.register_blueprint(shopping_bp)
        logger.info("Shopping blueprint initialized")
    except Exception as e:
        logger.error(f"Error initializing shopping blueprint: {str(e)}")
        raise
