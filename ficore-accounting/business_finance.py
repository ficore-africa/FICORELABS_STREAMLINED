from flask import Blueprint, jsonify, render_template, request, redirect, url_for
from utils import get_mongo_db, trans, requires_role, logger, is_admin
from models import get_user
from datetime import datetime
from bson import ObjectId

business = Blueprint('business', __name__, url_prefix='/business')

def get_notification_icon(notification_type):
    """Return appropriate icon for notification type."""
    icons = {
        'email': 'bi-envelope',
        'sms': 'bi-chat',
        'whatsapp': 'bi-whatsapp'
    }
    return icons.get(notification_type, 'bi-info-circle')

@business.route('/home', methods=['GET'])
@requires_role(['trader', 'admin'])
def home(user_id, email, lang='en'):
    """Render the Business Finance homepage with wallet balance and summaries."""
    try:
        db = get_mongo_db()
        # Verify user exists and matches email
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return render_template(
                'personal/GENERAL/error.html',
                error=trans('user_not_found', default='User not found', lang=lang),
                title=trans('error', default='Error', lang=lang)
            ), 404

        # Fetch Ficore Credit balance
        user_doc = db.users.find_one({'_id': user_id, 'email': email})
        ficore_credit_balance = user_doc.get('ficore_credit_balance', 0) if user_doc else 0

        # Fetch debt summary
        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0

        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0

        # Fetch cashflow summary
        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0

        payments_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments

        logger.info(f"Rendered business finance homepage for user_id={user_id}, email={email}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        
        return render_template(
            'general/home.html',
            ficore_credit_balance=ficore_credit_balance,
            total_i_owe=total_i_owe,
            total_i_am_owed=total_i_am_owed,
            net_cashflow=net_cashflow,
            total_receipts=total_receipts,
            total_payments=total_payments,
            title=trans('business_home', default='Business Finance', lang=lang),
            format_currency=utils.format_currency
        )
    except Exception as e:
        logger.error(f"Error rendering business homepage for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return render_template(
            'personal/GENERAL/error.html',
            error=trans('dashboard_error', default='Error loading dashboard', lang=lang),
            title=trans('error', default='Error', lang=lang)
        ), 500

@business.route('/credits/get_balance', methods=['GET'])
@requires_role(['trader', 'admin'])
def get_balance(user_id, email):
    """Fetch the Ficore Credit balance for the authenticated user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        user_doc = db.users.find_one({'_id': user_id, 'email': email})
        ficore_credit_balance = user_doc.get('ficore_credit_balance', 0) if user_doc else 0
        logger.info(f"Fetched Ficore Credit balance for user_id={user_id}, email={email}: {ficore_credit_balance}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'ficore_credit_balance': ficore_credit_balance}), 200
    except Exception as e:
        logger.error(f"Error fetching Ficore Credit balance for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('ficore_credit_balance_error', default='Error fetching balance')}), 500

@business.route('/notifications/count', methods=['GET'])
@requires_role(['trader', 'admin'])
@utils.limiter.limit('10 per minute')
def notification_count(user_id, email):
    """Fetch the count of unread notifications for the authenticated business user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        count = db.bill_reminders.count_documents({'user_id': user_id, 'email': email, 'read_status': False})
        logger.info(f"Fetched notification count for user_id={user_id}, email={email}: {count}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'count': count}), 200
    except Exception as e:
        logger.error(f"Notification count error for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('notification_count_error', default='Error fetching notification count')}), 500

@business.route('/notifications', methods=['GET'])
@requires_role(['trader', 'admin'])
@utils.limiter.limit('10 per minute')
def notifications(user_id, email, lang='en'):
    """Fetch notifications for the authenticated business user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        notifications = list(db.bill_reminders.find({'user_id': user_id, 'email': email}).sort('sent_at', -1).limit(10))
        logger.info(f"Fetched {len(notifications)} notifications for user_id={user_id}, email={email}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        result = [{
            'id': str(n['notification_id']),
            'message': trans(n['message'], lang=lang, default=n['message']),
            'type': n['type'],
            'timestamp': n['sent_at'].isoformat(),
            'read': n.get('read_status', False)
        } for n in notifications]
        notification_ids = [n['notification_id'] for n in notifications if not n.get('read_status', False)]
        if notification_ids:
            db.bill_reminders.update_many(
                {'notification_id': {'$in': notification_ids}, 'user_id': user_id, 'email': email},
                {'$set': {'read_status': True}}
            )
            logger.info(f"Marked {len(notification_ids)} notifications read for user_id={user_id}, email={email}", 
                        extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        notification = result[0] if result else None
        return jsonify({'notifications': result, 'notification': notification}), 200
    except Exception as e:
        logger.error(f"Notifications error for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('notifications_error', default='Error fetching notifications')}), 500

@business.route('/recent_notifications', methods=['GET'])
@requires_role(['trader', 'admin'])
def recent_notifications(user_id, email):
    """Fetch recent notifications for the authenticated business user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        reminders = db.bill_reminders.find({
            'user_id': user_id,
            'email': email,
            'sent_at': {'$exists': True}
        }).sort('sent_at', -1).limit(5)
        notifications = [
            {
                'message': reminder.get('message', ''),
                'timestamp': reminder.get('sent_at').isoformat(),
                'icon': get_notification_icon(reminder.get('type', 'info')),
                'read': reminder.get('read_status', False)
            } for reminder in reminders
        ]
        logger.info(f"Fetched recent notifications for user_id={user_id}, email={email}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify(notifications), 200
    except Exception as e:
        logger.error(f"Error fetching recent notifications for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('notifications_error', default='Error fetching notifications')}), 500

@business.route('/debt/summary', methods=['GET'])
@requires_role(['trader', 'admin'])
def debt_summary(user_id, email):
    """Fetch debt summary (I Owe, I Am Owed) for the authenticated user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0

        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0

        logger.info(f"Fetched debt summary for user_id={user_id}, email={email}: I Owe={total_i_owe}, I Am Owed={total_i_am_owed}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({
            'totalIOwe': total_i_owe,
            'totalIAmOwed': total_i_am_owed
        }), 200
    except Exception as e:
        logger.error(f"Error fetching debt summary for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('debt_summary_error', default='Error fetching debt summary')}), 500

@business.route('/cashflow/summary', methods=['GET'])
@requires_role(['trader', 'admin'])
def cashflow_summary(user_id, email):
    """Fetch the net cashflow (month-to-date) for the authenticated user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0

        payments_pipeline = [
            {'$match': {'user_id': user_id, 'email': email, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments

        logger.info(f"Fetched cashflow summary for user_id={user_id}, email={email}: Net Cashflow={net_cashflow}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({
            'netCashflow': net_cashflow,
            'totalReceipts': total_receipts,
            'totalPayments': total_payments
        }), 200
    except Exception as e:
        logger.error(f"Error fetching cashflow summary for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('cashflow_error', default='Error fetching cashflow summary')}), 500

@business.route('/recent_activity', methods=['GET'])
@requires_role(['trader', 'admin'])
def recent_activity(user_id, email):
    """Fetch recent activities (debts, cashflows) for the authenticated user."""
    try:
        db = get_mongo_db()
        user = get_user(db, user_id, email)
        if not user:
            logger.error(f"User not found: user_id={user_id}, email={email}", 
                         extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
            return jsonify({'error': trans('user_not_found', default='User not found')}), 404

        activities = []
        # Fetch recent debt records
        records = db.records.find({'user_id': user_id, 'email': email}).sort('created_at', -1).limit(3)
        for record in records:
            activity_type = 'debt_added' if record.get('type') == 'debtor' else 'trader_registered'
            description = f'{"Owe" if record.get("type") == "debtor" else "Owed by"} {record.get("name")}'
            activities.append({
                'type': activity_type,
                'description': description,
                'amount': record.get('amount_owed', 0),
                'timestamp': record.get('created_at').isoformat()
            })

        # Fetch recent cashflows
        cashflows = db.cashflows.find({'user_id': user_id, 'email': email}).sort('created_at', -1).limit(3)
        for cashflow in cashflows:
            activity_type = 'money_in' if cashflow.get('type') == 'receipt' else 'money_out'
            description = f'{"Received from" if cashflow.get("type") == "receipt" else "Paid to"} {cashflow.get("party_name")}'
            activities.append({
                'type': activity_type,
                'description': description,
                'amount': cashflow.get('amount', 0),
                'timestamp': cashflow.get('created_at').isoformat()
            })

        # Sort activities by timestamp (descending)
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        activities = activities[:5]

        logger.info(f"Fetched {len(activities)} recent activities for user_id={user_id}, email={email}", 
                    extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify(activities), 200
    except Exception as e:
        logger.error(f"Error fetching recent activity for user_id={user_id}, email={email}: {str(e)}", 
                     extra={'user_id': user_id, 'email': email, 'ip_address': request.remote_addr})
        return jsonify({'error': trans('activity_error', default='Error fetching recent activity')}), 500
