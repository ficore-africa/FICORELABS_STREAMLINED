from flask import Blueprint, jsonify, render_template, session, request, redirect, url_for
from flask_login import current_user, login_required
from datetime import datetime
import utils
from utils import logger

business = Blueprint('business', __name__, url_prefix='/business')

def get_notification_icon(notification_type):
    """Return appropriate icon for notification type."""
    icons = {
        'email': 'bi-envelope',
        'sms': 'bi-chat',
        'whatsapp': 'bi-whatsapp'
    }
    return icons.get(notification_type, 'bi-info-circle')

@business.route('/home')
@login_required
@utils.requires_role(['trader', 'admin'])
def home():
    """Render the Business Finance homepage with wallet balance and summaries."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        lang = session.get('lang', 'en')

        # Fetch Ficore Credit balance
        user = db.users.find_one({'_id': user_id})
        ficore_credit_balance = user.get('ficore_credit_balance', 0) if user else 0

        # Fetch debt summary
        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0
        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0

        # Fetch cashflow summary
        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0
        payments_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments

        logger.info(f"Rendered business finance homepage for user {user_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        
        return render_template(
            'general/home.html',
            ficore_credit_balance=ficore_credit_balance,  # Updated variable name
            total_i_owe=total_i_owe,
            total_i_am_owed=total_i_am_owed,
            net_cashflow=net_cashflow,
            total_receipts=total_receipts,
            total_payments=total_payments,
            title=utils.trans('business_home', lang=lang),
            format_currency=utils.format_currency
        )
    except Exception as e:
        logger.error(f"Error rendering business homepage for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return render_template(
            'personal/GENERAL/error.html',
            error=utils.trans('dashboard_error', lang=lang),
            title=utils.trans('error', lang=lang)
        ), 500

@business.route('/credits/get_balance')
@login_required
@utils.requires_role(['trader', 'admin'])
def get_balance():
    return redirect(url_for('credits.get_balance'))
# COMMENT OUT DUPLICATE BALANCE API CALLS FOR NOW, LET IT USE THE ONE FROM CREDITS BLUEPRINT
#"""Fetch the Ficore Credit balance for the authenticated user."""
 #   try:
  #      db = utils.get_mongo_db()
   #     user = db.users.find_one({'_id': current_user.id})
    #    ficore_credit_balance = user.get('ficore_credit_balance', 0) if user else 0
     #   logger.info(f"Fetched Ficore Credit balance for user {current_user.id}: {ficore_credit_balance}", 
      #              extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
       # return jsonify({'ficore_credit_balance': ficore_credit_balance})
    #except Exception as e:
     #   logger.error(f"Error fetching Ficore Credit balance for user {current_user.id}: {str(e)}", 
      #               extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
       # return jsonify({'error': utils.trans('ficore_credit_balance_error')}), 500

# Other routes (notifications, debt, summary, etc.) remain unchanged
@business.route('/notifications/count')
@login_required
@utils.requires_role(['trader', 'admin'])
@utils.limiter.limit('10 per minute')
def notification_count():
    """Fetch the count of unread notifications for the authenticated business user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        count = db.bill_reminders.count_documents({'user_id': user_id, 'read_status': False})
        logger.info(f"Fetched notification count for user {user_id}: {count}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'count': count})
    except Exception as e:
        logger.error(f"Notification count error for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('notification_count_error')}), 500

@business.route('/notifications')
@login_required
@utils.requires_role(['trader', 'admin'])
@utils.limiter.limit('10 per minute')
def notifications():
    """Fetch notifications for the authenticated business user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        lang = session.get('lang', 'en')
        notifications = list(db.bill_reminders.find({'user_id': user_id}).sort('sent_at', -1).limit(10))
        logger.info(f"Fetched {len(notifications)} notifications for user {user_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        result = [{
            'id': str(n['notification_id']),
            'message': utils.trans(n['message'], lang=lang),
            'type': n['type'],
            'timestamp': n['sent_at'].isoformat(),
            'read': n.get('read_status', False)
        } for n in notifications]
        notification_ids = [n['notification_id'] for n in notifications if not n.get('read_status', False)]
        if notification_ids:
            db.bill_reminders.update_many(
                {'notification_id': {'$in': notification_ids}, 'user_id': user_id},
                {'$set': {'read_status': True}}
            )
            logger.info(f"Marked {len(notification_ids)} notifications read for user {user_id}", 
                        extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        notification = result[0] if result else None
        return jsonify({'notifications': result, 'notification': notification}), 200
    except Exception as e:
        logger.error(f"Notifications error for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('notifications_error')}), 500

@business.route('/recent_notifications')
@login_required
@utils.requires_role(['trader', 'admin'])
def recent_notifications():
    """Fetch recent notifications for the authenticated business user."""
    try:
        db = utils.get_mongo_db()
        reminders = db.bill_reminders.find({
            'user_id': current_user.id,
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
        logger.info(f"Fetched recent notifications for user {current_user.id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify(notifications)
    except Exception as e:
        logger.error(f"Error fetching recent notifications for user {current_user.id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('notifications_error')}), 500

@business.route('/debt/summary')
@login_required
@utils.requires_role(['trader', 'admin'])
def debt_summary():
    """Fetch debt summary (I Owe, I Am Owed) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0
        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0
        logger.info(f"Fetched debt summary for user {user_id}: I Owe={total_i_owe}, I Am Owed={total_i_am_owed}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({
            'totalIOwe': total_i_owe,
            'totalIAmOwed': total_i_am_owed
        })
    except Exception as e:
        logger.error(f"Error fetching debt summary for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('debt_summary_error')}), 500

@business.route('/cashflow/summary')
@login_required
@utils.requires_role(['trader', 'admin'])
def cashflow_summary():
    """Fetch the net cashflow (month-to-date) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0
        payments_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments
        logger.info(f"Fetched cashflow summary for user {user_id}: Net Cashflow={net_cashflow}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({
            'netCashflow': net_cashflow,
            'totalReceipts': total_receipts,
            'totalPayments': total_payments
        })
    except Exception as e:
        logger.error(f"Error fetching cashflow summary for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('cashflow_error')}), 500

@business.route('/recent_activity')
@login_required
@utils.requires_role(['trader', 'admin'])
def recent_activity():
    """Fetch recent activities (debts, cashflows) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        activities = []
        
        # Fetch recent debt records
        records = db.records.find({'user_id': user_id}).sort('created_at', -1).limit(3)
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
        cashflows = db.cashflows.find({'user_id': user_id}).sort('created_at', -1).limit(3)
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
        
        logger.info(f"Fetched {len(activities)} recent activities for user {user_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify(activities)
    except Exception as e:
        logger.error(f"Error fetching recent activity for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('activity_error')}), 500
