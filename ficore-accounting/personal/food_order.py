from flask import Blueprint, request, session, redirect, url_for, render_template, flash, current_app, jsonify, Response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, FloatField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Email
from flask_login import current_user, login_required
from datetime import datetime, timedelta
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
import uuid
import geocoder
import traceback
from models import log_tool_usage
from session_utils import create_anonymous_session

food_order_bp = Blueprint(
    'food_order',
    __name__,
    template_folder='templates/personal/FOOD_ORDER',
    url_prefix='/food_order'
)

csrf = CSRFProtect()

def deduct_ficore_credits(db, user_id, amount, action, order_id=None, mongo_session=None):
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
                    'order_id': str(order_id) if order_id else None,
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

def send_order_to_vendor(order):
    try:
        logger.info(f"Order {order['id']} sent to vendor {order['vendor']}: {order}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
    except Exception as e:
        logger.error(f"Error sending order {order['id']} to vendor: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})

def custom_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated or session.get('is_anonymous', False):
            return f(*args, **kwargs)
        return redirect(url_for('users.login', next=request.url))
    return decorated_function

class FoodOrderForm(FlaskForm):
    name = StringField(
        trans('food_order_name', default='Order Name'),
        validators=[DataRequired(message=trans('food_order_name_required', default='Order name is required'))]
    )
    vendor = StringField(
        trans('food_order_vendor', default='Vendor'),
        validators=[DataRequired(message=trans('food_order_vendor_required', default='Vendor is required'))]
    )
    phone = StringField(
        trans('food_order_phone', default='Phone Number'),
        validators=[DataRequired(message=trans('food_order_phone_required', default='Phone number is required'))]
    )
    location = StringField(
        trans('food_order_location', default='Delivery Location'),
        validators=[DataRequired(message=trans('food_order_location_required', default='Delivery location is required'))]
    )
    submit = SubmitField(trans('food_order_submit', default='Create Order'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('food_order_name', lang) or 'Order Name'
        self.vendor.label.text = trans('food_order_vendor', lang) or 'Vendor'
        self.phone.label.text = trans('food_order_phone', lang) or 'Phone Number'
        self.location.label.text = trans('food_order_location', lang) or 'Delivery Location'
        self.submit.label.text = trans('food_order_submit', lang) or 'Create Order'

class FoodOrderItemForm(FlaskForm):
    name = StringField(
        trans('food_order_item_name', default='Item Name'),
        validators=[DataRequired(message=trans('food_order_item_name_required', default='Item name is required'))]
    )
    quantity = IntegerField(
        trans('food_order_quantity', default='Quantity'),
        validators=[
            DataRequired(message=trans('food_order_quantity_required', default='Quantity is required')),
            NumberRange(min=1, max=1000, message=trans('food_order_quantity_range', default='Quantity must be between 1 and 1000'))
        ]
    )
    price = FloatField(
        trans('food_order_price', default='Price'),
        filters=[clean_currency],
        validators=[
            DataRequired(message=trans('food_order_price_required', default='Price is required')),
            NumberRange(min=0, max=1000000, message=trans('food_order_price_range', default='Price must be between 0 and 1 million'))
        ]
    )
    notes = StringField(trans('food_order_item_notes', default='Item Notes'))
    submit = SubmitField(trans('food_order_item_submit', default='Add Item'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        self.name.label.text = trans('food_order_item_name', lang) or 'Item Name'
        self.quantity.label.text = trans('food_order_quantity', lang) or 'Quantity'
        self.price.label.text = trans('food_order_price', lang) or 'Price'
        self.notes.label.text = trans('food_order_item_notes', lang) or 'Item Notes'
        self.submit.label.text = trans('food_order_item_submit', lang) or 'Add Item'

@food_order_bp.route('/main', methods=['GET', 'POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def main():
    if 'sid' not in session:
        create_anonymous_session()
        session['is_anonymous'] = True
        logger.debug(f"New anonymous session created with sid: {session['sid']}", extra={'session_id': session['sid']})
    session.permanent = True
    session.modified = True
    order_form = FoodOrderForm()
    item_form = FoodOrderItemForm()
    db = get_mongo_db()

    valid_tabs = ['create-order', 'dashboard']
    active_tab = request.args.get('tab', 'create-order')
    if active_tab not in valid_tabs:
        active_tab = 'create-order'

    try:
        log_tool_usage(
            tool_name='food_order',
            db=db,
            user_id=current_user.id if current_user.is_authenticated else None,
            session_id=session.get('sid', 'no-session-id'),
            action='main_view'
        )
    except Exception as e:
        logger.error(f"Failed to log tool usage: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id')})
        flash(trans('food_order_log_error', default='Error logging food order activity. Please try again.'), 'warning')

    filter_criteria = {} if is_admin() else {'user_id': str(current_user.id)} if current_user.is_authenticated else {'session_id': session['sid']}
    orders = []
    latest_order = None
    categories = {}
    items = []

    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'create_order' and order_form.validate_on_submit():
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for creating order by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to create an order. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                recent_order = db.FoodOrder.find_one({
                    **filter_criteria,
                    'created_at': {'$gte': datetime.utcnow() - timedelta(minutes=5)}
                })
                if recent_order:
                    logger.warning(f"Duplicate order attempt by user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                                  extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_duplicate', default='Please wait 5 minutes before creating another order'), 'warning')
                    return redirect(url_for('personal.food_order.main', tab='create-order'))
                order_data = {
                    'id': str(uuid.uuid4()),
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session['sid'],
                    'name': order_form.name.data,
                    'vendor': order_form.vendor.data,
                    'phone': order_form.phone.data,
                    'location': order_form.location.data,
                    'total_cost': 0.0,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                    'shared_with': [],
                    'items': [],
                    'status': 'submitted'
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.FoodOrder.insert_one(order_data, session=mongo_session)
                            if current_user.is_authenticated and not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, 0.1, 'create_food_order', order_data['id'], mongo_session):
                                    db.FoodOrder.delete_one({'id': order_data['id']}, session=mongo_session)
                                    logger.error(f"Failed to deduct 0.1 Ficore Credits for creating order {order_data['id']}", 
                                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                    flash(trans('food_order_credit_deduction_failed', default='Failed to deduct Ficore Credits for creating order.'), 'danger')
                                    return redirect(url_for('personal.food_order.main', tab='create-order'))
                    send_order_to_vendor(order_data)
                    logger.info(f"Created food order {order_data['id']} for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_created', default='Food order created successfully!'), 'success')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                except Exception as e:
                    logger.error(f"Failed to save food order {order_data['id']}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_error', default='Error saving food order.'), 'danger')

            elif action == 'add_item' and item_form.validate_on_submit():
                order_id = request.form.get('order_id')
                try:
                    uuid.UUID(order_id)
                except ValueError:
                    flash(trans('food_order_invalid_order_id', default='Invalid order ID format.'), 'danger')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                order = db.FoodOrder.find_one({'id': order_id, **filter_criteria})
                if not order:
                    flash(trans('food_order_not_found', default='Order not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for adding item to order {order_id} by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to add an item. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                item_data = {
                    'item_id': str(uuid.uuid4()),
                    'name': item_form.name.data,
                    'quantity': item_form.quantity.data,
                    'price': item_form.price.data,
                    'notes': item_form.notes.data,
                    'category': 'Uncategorized'
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            result = db.FoodOrder.update_one(
                                {'id': order_id},
                                {
                                    '$push': {'items': item_data},
                                    '$set': {
                                        'total_cost': order['total_cost'] + (item_data['quantity'] * item_data['price']),
                                        'updated_at': datetime.utcnow()
                                    }
                                },
                                session=mongo_session
                            )
                            if current_user.is_authenticated and not is_admin():
                                if not deduct_ficore_credits(db, current_user.id, 0.1, 'add_food_order_item', item_data['item_id'], mongo_session):
                                    db.FoodOrder.update_one(
                                        {'id': order_id},
                                        {
                                            '$pull': {'items': {'item_id': item_data['item_id']}},
                                            '$set': {'updated_at': datetime.utcnow()}
                                        },
                                        session=mongo_session
                                    )
                                    logger.error(f"Failed to deduct 0.1 Ficore Credits for adding item {item_data['item_id']} to order {order_id}", 
                                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                                    flash(trans('food_order_credit_deduction_failed', default='Failed to deduct Ficore Credits for adding item.'), 'danger')
                                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                    send_order_to_vendor(db.FoodOrder.find_one({'id': order_id}))
                    flash(trans('food_order_item_added', default='Item added successfully!'), 'success')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                except Exception as e:
                    logger.error(f"Failed to add item to order {order_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_item_error', default='Error adding item.'), 'danger')

            elif action == 'delete_order':
                order_id = request.form.get('order_id')
                try:
                    uuid.UUID(order_id)
                except ValueError:
                    flash(trans('food_order_invalid_order_id', default='Invalid order ID format.'), 'danger')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                order = db.FoodOrder.find_one({'id': order_id, **filter_criteria})
                if not order:
                    flash(trans('food_order_not_found', default='Order not found or you are not the owner.'), 'danger')
                    return redirect(url_for('personal.food_order.main', tab='dashboard'))
                if current_user.is_authenticated and not is_admin():
                    if not check_ficore_credit_balance(required_amount=0.5, user_id=current_user.id):
                        logger.warning(f"Insufficient Ficore Credits for deleting order {order_id} by user {current_user.id}", 
                                      extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to delete an order. Please purchase more credits.'), 'danger')
                        return redirect(url_for('agents_bp.manage_credits'))
                deletion_data = {
                    'order_id': order_id,
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session['sid'],
                    'created_at': datetime.utcnow(),
                    'expires_at': datetime.utcnow() + timedelta(seconds=20)
                }
                try:
                    with db.client.start_session() as mongo_session:
                        with mongo_session.start_transaction():
                            db.pending_deletions.insert_one(deletion_data, session=mongo_session)
                            threading.Thread(target=process_delayed_deletion, args=(order_id, current_user.id if current_user.is_authenticated else None)).start()
                    logger.info(f"Initiated delayed deletion for food order {order_id}", 
                                extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_deletion_initiated', default='Food order deletion initiated. Will delete in 20 seconds.'), 'success')
                except Exception as e:
                    logger.error(f"Error initiating deletion of order {order_id}: {str(e)}", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    flash(trans('food_order_error', default='Error initiating deletion.'), 'danger')
                return redirect(url_for('personal.food_order.main', tab='dashboard'))

        orders = list(db.FoodOrder.find(filter_criteria).sort('created_at', -1).limit(10))
        orders_dict = {}
        for order in orders:
            order_data = {
                'id': order['id'],
                'name': order.get('name'),
                'vendor': order.get('vendor'),
                'phone': order.get('phone'),
                'location': order.get('location'),
                'total_cost': format_currency(order.get('total_cost', 0.0)),
                'total_cost_raw': float(order.get('total_cost', 0.0)),
                'created_at': order.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if order.get('created_at') else 'N/A',
                'status': order.get('status', 'submitted'),
                'items': [{
                    'item_id': item['item_id'],
                    'name': item.get('name'),
                    'quantity': item.get('quantity', 1),
                    'price': format_currency(item.get('price', 0.0)),
                    'price_raw': float(item.get('price', 0.0)),
                    'notes': item.get('notes', ''),
                    'category': item.get('category', 'Uncategorized')
                } for item in order.get('items', [])]
            }
            orders_dict[order_data['id']] = order_data
            if not latest_order or (order.get('created_at') and (latest_order['created_at'] == 'N/A' or order.get('created_at') > datetime.strptime(latest_order['created_at'], '%Y-%m-%d %H:%M:%S'))):
                latest_order = order_data
                items = order_data['items']
                logger.debug(f"latest_order.items type: {type(order_data['items'])}, value: {order_data['items']}", 
                             extra={'session_id': session.get('sid', 'no-session-id')})
                categories = {
                    trans('food_order_category_uncategorized', default='Uncategorized'): sum(item['price_raw'] * item['quantity'] for item in items if item['category'] == 'Uncategorized')
                }
                categories = {k: v for k, v in categories.items() if v > 0}

        if not latest_order:
            latest_order = {
                'id': None,
                'name': '',
                'vendor': '',
                'phone': '',
                'location': '',
                'total_cost': format_currency(0.0),
                'total_cost_raw': 0.0,
                'created_at': 'N/A',
                'status': 'submitted',
                'items': []
            }
            items = []

        total_orders = len(orders_dict)
        total_spent = sum(order['total_cost_raw'] for order in orders_dict.values())
        pending_orders = sum(1 for order in orders_dict.values() if order['status'] == 'submitted')

        tips = [
            trans('food_order_tip_check_menu', default='Check the vendor’s menu for the latest items and prices.'),
            trans('food_order_tip_delivery_time', default='Order early to ensure timely delivery.'),
            trans('food_order_tip_notes', default='Use notes to specify preferences like "no onions".'),
            trans('food_order_tip_reorder', default='Use reorder for frequent orders to save time.')
        ]
        insights = []
        if total_spent > 1000:
            insights.append(trans('food_order_insight_high_spending', default='Your food order spending is high. Consider budget-friendly options.'))

        return render_template(
            'personal/FOOD_ORDER/food_order_main.html',
            order_form=order_form,
            item_form=item_form,
            orders=orders_dict,
            latest_order=latest_order,
            items=items,  # Explicitly pass items
            categories=categories,
            total_orders=total_orders,
            total_spent=format_currency(total_spent),
            pending_orders=pending_orders,
            tips=tips,
            insights=insights,
            tool_title=trans('food_order_title', default='Food Order Manager'),
            active_tab=active_tab
        )
    except Exception as e:
        logger.error(f"Unexpected error in food_order.main: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr, 'stack_trace': traceback.format_exc()})
        flash(trans('food_order_dashboard_load_error', default='Error loading food order dashboard.'), 'danger')
        return render_template(
            'personal/FOOD_ORDER/food_order_main.html',
            order_form=order_form,
            item_form=item_form,
            orders={},
            latest_order={
                'id': None,
                'name': '',
                'vendor': '',
                'phone': '',
                'location': '',
                'total_cost': format_currency(0.0),
                'total_cost_raw': 0.0,
                'created_at': 'N/A',
                'status': 'submitted',
                'items': []
            },
            items=[],  # Explicitly pass empty items
            categories={},
            total_orders=0,
            total_spent=format_currency(0.0),
            pending_orders=0,
            tips=[],
            insights=[],
            tool_title=trans('food_order_title', default='Food Order Manager'),
            active_tab=active_tab
        ), 500

@food_order_bp.route('/get_nearest_vendor', methods=['GET'])
@custom_login_required
@requires_role(['personal', 'admin'])
def get_nearest_vendor():
    try:
        location = request.args.get('location')
        if not location:
            logger.error(f"Missing location parameter", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_missing_location', default='Location required')}), 400
        try:
            lat, lng = map(float, location.split(','))
        except ValueError:
            logger.error(f"Invalid location format: {location}", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_invalid_location', default='Invalid location format')}), 400
        db = get_mongo_db()
        vendors = db.vendors.find()
        nearest_vendor = None
        min_distance = float('inf')
        for vendor in vendors:
            vendor_loc = vendor.get('location', {})
            if 'lat' not in vendor_loc or 'lng' not in vendor_loc:
                continue
            distance = ((lat - vendor_loc['lat'])**2 + (lng - vendor_loc['lng'])**2)**0.5
            if distance < min_distance:
                min_distance = distance
                nearest_vendor = vendor['name']
        if nearest_vendor:
            logger.info(f"Found nearest vendor {nearest_vendor} for location {location}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'vendor': nearest_vendor})
        else:
            logger.warning(f"No vendors found near location {location}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_no_vendors', default='No vendors found nearby')}), 404
    except Exception as e:
        logger.error(f"Error finding nearest vendor: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': trans('general_error', default='An error occurred')}), 500

@food_order_bp.route('/reorder/<order_id>', methods=['POST'])
@custom_login_required
@requires_role(['personal', 'admin'])
def reorder(order_id):
    try:
        try:
            uuid.UUID(order_id)
        except ValueError:
            logger.error(f"Invalid order_id {order_id}: not a valid UUID", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_invalid_order_id', default='Invalid order ID'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        db = get_mongo_db()
        order = db.FoodOrder.find_one({'id': order_id, **({'user_id': str(current_user.id)} if current_user.is_authenticated else {'session_id': session['sid']})})
        if not order:
            logger.warning(f"Order {order_id} not found for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_not_found', default='Order not found or you are not the owner.'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        recent_order = db.FoodOrder.find_one({
            **({'user_id': str(current_user.id)} if current_user.is_authenticated else {'session_id': session['sid']}),
            'created_at': {'$gte': datetime.utcnow() - timedelta(minutes=5)}
        })
        if recent_order:
            logger.warning(f"Duplicate order attempt by user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_duplicate', default='Please wait 5 minutes before creating another order'), 'warning')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        if current_user.is_authenticated and not is_admin():
            if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                logger.warning(f"Insufficient Ficore Credits for reordering order {order_id} by user {current_user.id}", 
                              extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                flash(trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to reorder. Please purchase more credits.'), 'danger')
                return redirect(url_for('agents_bp.manage_credits'))
        new_order = {
            'id': str(uuid.uuid4()),
            'user_id': str(current_user.id) if current_user.is_authenticated else None,
            'session_id': session['sid'],
            'name': order['name'],
            'vendor': order['vendor'],
            'phone': order['phone'],
            'location': order['location'],
            'total_cost': order['total_cost'],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'shared_with': [],
            'items': order['items'],
            'status': 'submitted'
        }
        try:
            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    db.FoodOrder.insert_one(new_order, session=mongo_session)
                    if current_user.is_authenticated and not is_admin():
                        if not deduct_ficore_credits(db, current_user.id, 0.1, 'reorder_food_order', new_order['id'], mongo_session):
                            db.FoodOrder.delete_one({'id': new_order['id']}, session=mongo_session)
                            logger.error(f"Failed to deduct 0.1 Ficore Credits for reordering order {new_order['id']}", 
                                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                            flash(trans('food_order_credit_deduction_failed', default='Failed to deduct Ficore Credits for reordering.'), 'danger')
                            return redirect(url_for('personal.food_order.main', tab='dashboard'))
            send_order_to_vendor(new_order)
            logger.info(f"Reordered order {order_id} as new order {new_order['id']} for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_reordered', default='Order reordered successfully!'), 'success')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        except Exception as e:
            logger.error(f"Error reordering order {order_id}: {str(e)}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_error', default='Error reordering order.'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
    except Exception as e:
        logger.error(f"Unexpected error in reorder: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        flash(trans('general_error', default='An error occurred'), 'danger')
        return redirect(url_for('personal.food_order.main', tab='dashboard'))

@food_order_bp.route('/manage_items/<order_id>', methods=['PUT'])
@custom_login_required
@requires_role(['personal', 'admin'])
def manage_items(order_id):
    try:
        try:
            uuid.UUID(order_id)
        except ValueError:
            logger.error(f"Invalid order_id {order_id}: not a valid UUID", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_invalid_order_id', default='Invalid order ID')}), 400
        db = get_mongo_db()
        order = db.FoodOrder.find_one({'id': order_id, **({'user_id': str(current_user.id)} if current_user.is_authenticated else {'session_id': session['sid']})})
        if not order:
            logger.warning(f"Order {order_id} not found for user {current_user.id if current_user.is_authenticated else 'anonymous'}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_not_found', default='Order not found')}), 404
        data = request.get_json()
        if not data or not data.get('item_id') or not data.get('field') or data.get('field') not in ['quantity', 'price', 'notes']:
            logger.warning(f"Invalid update data: {data}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_invalid_update_data', default='Invalid update data')}), 400
        item_id = data['item_id']
        field = data['field']
        value = data[field]
        if current_user.is_authenticated and not is_admin() and field != 'notes':
            if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                logger.warning(f"Insufficient Ficore Credits for updating item {item_id} in order {order_id} by user {current_user.id}", 
                              extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                return jsonify({'error': trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to update an item. Please purchase more credits.')}), 403
        items = order.get('items', [])
        item_index = next((i for i, item in enumerate(items) if item['item_id'] == item_id), None)
        if item_index is None:
            logger.warning(f"Item {item_id} not found in order {order_id}", 
                          extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_item_not_found', default='Item not found')}), 404
        original_item = items[item_index].copy()
        items[item_index][field] = int(value) if field == 'quantity' else float(value) if field == 'price' else value
        total_cost = sum(item['quantity'] * item['price'] for item in items)
        try:
            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    result = db.FoodOrder.update_one(
                        {'id': order_id},
                        {
                            '$set': {
                                'items': items,
                                'total_cost': total_cost,
                                'updated_at': datetime.utcnow()
                            }
                        },
                        session=mongo_session
                    )
                    if current_user.is_authenticated and not is_admin() and field != 'notes':
                        if not deduct_ficore_credits(db, current_user.id, 0.1, 'update_food_order_item', item_id, mongo_session):
                            items[item_index] = original_item
                            total_cost = sum(item['quantity'] * item['price'] for item in items)
                            db.FoodOrder.update_one(
                                {'id': order_id},
                                {
                                    '$set': {
                                        'items': items,
                                        'total_cost': total_cost,
                                        'updated_at': datetime.utcnow()
                                    }
                                },
                                session=mongo_session
                            )
                            logger.error(f"Failed to deduct 0.1 Ficore Credits for updating item {item_id} in order {order_id}", 
                                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                            return jsonify({'error': trans('food_order_credit_deduction_failed', default='Failed to deduct Ficore Credits for updating item.')}), 500
            send_order_to_vendor(db.FoodOrder.find_one({'id': order_id}))
            logger.info(f"Updated item {item_id} in order {order_id}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error updating item {item_id} in order {order_id}: {str(e)}", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            return jsonify({'error': trans('food_order_item_error', default='Error updating item.')}), 500
    except Exception as e:
        logger.error(f"Unexpected error in manage_items: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': trans('general_error', default='An error occurred')}), 500

@food_order_bp.route('/export_pdf/<order_id>', methods=['GET'])
@login_required
@requires_role(['personal', 'admin'])
def export_order_pdf(order_id):
    db = get_mongo_db()
    try:
        try:
            uuid.UUID(order_id)
        except ValueError:
            logger.error(f"Invalid order_id {order_id}: not a valid UUID", 
                         extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('food_order_invalid_order_id', default='Invalid order ID'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        order = db.FoodOrder.find_one({'id': order_id, 'user_id': str(current_user.id)})
        if not order:
            flash(trans('food_order_not_found', default='Order not found or you are not the owner.'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        if order.get('status') != 'submitted':
            flash(trans('food_order_not_submitted', default='Order must be submitted before exporting to PDF.'), 'danger')
            return redirect(url_for('personal.food_order.main', tab='dashboard'))
        if current_user.is_authenticated and not is_admin():
            if not check_ficore_credit_balance(required_amount=0.1, user_id=current_user.id):
                logger.warning(f"Insufficient Ficore Credits for exporting order {order_id} to PDF by user {current_user.id}", 
                              extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                flash(trans('food_order_insufficient_credits', default='Insufficient Ficore Credits to export order to PDF. Please purchase more credits.'), 'danger')
                return redirect(url_for('agents_bp.manage_credits'))
        order_data = {
            'orders': [{
                'name': order.get('name'),
                'vendor': order.get('vendor'),
                'phone': order.get('phone'),
                'location': order.get('location'),
                'total_cost': float(order.get('total_cost', 0)),
                'created_at': order.get('created_at')
            }],
            'items': [{
                'name': item.get('name'),
                'quantity': item.get('quantity', 1),
                'price': float(item.get('price', 0)),
                'notes': item.get('notes', ''),
                'category': item.get('category', 'Uncategorized')
            } for item in order.get('items', [])]
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
                total_cost = float(order_data['orders'][0]['total_cost'])
                def draw_order_headers(y):
                    p.setFillColor(colors.black)
                    p.drawString(1 * inch, y * inch, trans('general_date', default='Date'))
                    p.drawString(2 * inch, y * inch, trans('food_order_name', default='Order Name'))
                    p.drawString(3.5 * inch, y * inch, trans('food_order_vendor', default='Vendor'))
                    p.drawString(4.5 * inch, y * inch, trans('food_order_phone', default='Phone'))
                    p.drawString(5.5 * inch, y * inch, trans('food_order_location', default='Location'))
                    return y - row_height
                def draw_item_headers(y):
                    p.setFillColor(colors.black)
                    p.drawString(1 * inch, y * inch, trans('food_order_item_name', default='Item Name'))
                    p.drawString(2.5 * inch, y * inch, trans('food_order_quantity', default='Quantity'))
                    p.drawString(3.3 * inch, y * inch, trans('food_order_price', default='Price'))
                    p.drawString(4.0 * inch, y * inch, trans('food_order_notes', default='Notes'))
                    p.drawString(5.5 * inch, y * inch, trans('food_order_category', default='Category'))
                    return y - row_height
                p.setFont("Helvetica", 12)
                p.drawString(1 * inch, title_y * inch, trans('food_order_report', default='Food Order Report'))
                p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
                y = title_y - 0.6
                p.setFont("Helvetica", 10)
                y = draw_order_headers(y)
                row_count = 0
                order_info = order_data['orders'][0]
                p.drawString(1 * inch, y * inch, format_date(order_info['created_at']))
                p.drawString(2 * inch, y * inch, order_info['name'])
                p.drawString(3.5 * inch, y * inch, order_info['vendor'])
                p.drawString(4.5 * inch, y * inch, order_info['phone'])
                p.drawString(5.5 * inch, y * inch, order_info['location'])
                y -= row_height
                row_count += 1
                y -= 0.5
                p.drawString(1 * inch, y * inch, trans('food_order_items', default='Items'))
                y -= row_height
                y = draw_item_headers(y)
                for item in order_data['items']:
                    if row_count + 1 >= rows_per_page:
                        p.showPage()
                        y = title_y - 0.6
                        y = draw_item_headers(y)
                        row_count = 0
                    p.drawString(1 * inch, y * inch, item['name'][:20])
                    p.drawString(2.5 * inch, y * inch, str(item['quantity']))
                    p.drawString(3.3 * inch, y * inch, format_currency(item['price']))
                    p.drawString(4.0 * inch, y * inch, item['notes'][:20])
                    p.drawString(5.5 * inch, y * inch, trans(item['category'], default=item['category']))
                    y -= row_height
                    row_count += 1
                if row_count + 1 <= rows_per_page:
                    y -= row_height
                    p.drawString(1 * inch, y * inch, f"{trans('food_order_total_cost', default='Total Cost')}: {format_currency(total_cost)}")
                else:
                    p.showPage()
                    y = title_y - 0.6
                    p.drawString(1 * inch, y * inch, f"{trans('food_order_total_cost', default='Total Cost')}: {format_currency(total_cost)}")
                p.save()
                buffer.seek(0)
                if current_user.is_authenticated and not is_admin():
                    if not deduct_ficore_credits(db, current_user.id, 0.1, 'export_food_order_pdf', order_id, mongo_session):
                        logger.error(f"Failed to deduct 0.1 Ficore Credits for exporting order {order_id} to PDF by user {current_user.id}", 
                                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        flash(trans('food_order_credit_deduction_failed', default='Failed to deduct Ficore Credits for exporting order to PDF.'), 'danger')
                        return redirect(url_for('personal.food_order.main', tab='dashboard'))
        logger.info(f"Exported food order {order_id} to PDF for user {current_user.id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=food_order_{order_id}.pdf'})
    except Exception as e:
        logger.error(f"Error exporting order {order_id} to PDF: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        flash(trans('food_order_export_error', default='Error exporting food order to PDF.'), 'danger')
        return redirect(url_for('personal.food_order.main', tab='dashboard'))

def process_delayed_deletion(order_id, user_id):
    db = get_mongo_db()
    try:
        with db.client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                pending = db.pending_deletions.find_one({'order_id': order_id, 'user_id': str(user_id) if user_id else None}, session=mongo_session)
                if not pending:
                    return
                order = db.FoodOrder.find_one({'id': order_id, 'user_id': str(user_id) if user_id else None}, session=mongo_session)
                if not order:
                    db.pending_deletions.delete_one({'order_id': order_id}, session=mongo_session)
                    return
                result = db.FoodOrder.delete_one({'id': order_id}, session=mongo_session)
                if result.deleted_count == 0:
                    logger.error(f"Failed to delete food order {order_id}: No documents deleted", 
                                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                    raise ValueError(f"Failed to delete food order {order_id}")
                db.pending_deletions.delete_one({'order_id': order_id}, session=mongo_session)
                if user_id and not is_admin():
                    if not deduct_ficore_credits(db, user_id, 0.5, 'delete_food_order', order_id, mongo_session):
                        logger.error(f"Failed to deduct 0.5 Ficore Credits for deleting order {order_id} by user {user_id}", 
                                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
                        raise ValueError(f"Failed to deduct Ficore Credits for deleting order {order_id}")
        logger.info(f"Completed delayed deletion of food order {order_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
    except Exception as e:
        logger.error(f"Error in delayed deletion of order {order_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})

@food_order_bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error(f"CSRF error on {request.path}: {e.description}", 
                 extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
    flash(trans('food_order_csrf_error', default='Form submission failed due to a missing security token. Please refresh and try again.'), 'danger')
    return redirect(url_for('personal.food_order.main', tab='create-order')), 403

def init_app(app):
    try:
        db = get_mongo_db()
        db.FoodOrder.create_index([('user_id', 1), ('status', 1), ('updated_at', -1)])
        db.FoodOrder.create_index([('id', 1)])
        db.pending_deletions.create_index([('order_id', 1), ('user_id', 1)])
        app.register_blueprint(food_order_bp)
        logger.info("Initialized food order blueprint", extra={'session_id': 'no-request-context'})
    except Exception as e:
        logger.error(f"Error initializing food order blueprint: {str(e)}", 
                     extra={'session_id': 'no-request-context', 'stack_trace': traceback.format_exc()})
        raise
