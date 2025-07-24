from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
def index():
    """Display the user's dashboard with recent activity and role-specific content."""
    try:
        db = utils.get_mongo_db()
        
        # Determine query based on user role
        query = {} if utils.is_admin() else {'user_id': str(current_user.id)}

        # Initialize data containers
        recent_creditors = []
        recent_debtors = []
        recent_payments = []
        recent_receipts = []
        personal_finance_summary = {}

        # Fetch data based on user role
        if current_user.role in ['trader', 'admin']:
            # Fetch recent data using new schema for traders and admins
            recent_creditors = list(db.records.find({**query, 'type': 'creditor'}).sort('created_at', -1).limit(5))
            recent_debtors = list(db.records.find({**query, 'type': 'debtor'}).sort('created_at', -1).limit(5))
            recent_payments = list(db.cashflows.find({**query, 'type': 'payment'}).sort('created_at', -1).limit(5))
            recent_receipts = list(db.cashflows.find({**query, 'type': 'receipt'}).sort('created_at', -1).limit(5))

        if current_user.role in ['personal', 'admin']:
            # Fetch personal finance data for personal users and admins
            try:
                # Get latest records from each personal finance tool
                latest_budget = db.budgets.find_one(query, sort=[('created_at', -1)])
                latest_bill = db.bills.find_one(query, sort=[('created_at', -1)])

                # Count total records
                total_budgets = db.budgets.count_documents(query)
                total_bills = db.bills.count_documents(query)
                overdue_bills = db.bills.count_documents({**query, 'status': 'overdue'})
                
                personal_finance_summary = {
                    'latest_budget': latest_budget,
                    'latest_bill': latest_bill,
                    'total_budgets': total_budgets,
                    'total_bills': total_bills,
                    'overdue_bills': overdue_bills,
                    'has_personal_data': any([latest_budget, latest_bill])
                }
            except Exception as e:
                logger.error(f"Error fetching personal finance data for user {current_user.id}: {str(e)}")
                personal_finance_summary = {'has_personal_data': False}

        # Convert ObjectIds to strings for template rendering
        for item in recent_creditors + recent_debtors + recent_payments + recent_receipts:
            item['_id'] = str(item['_id'])

        return render_template(
            'dashboard/index.html',
            recent_creditors=recent_creditors,
            recent_debtors=recent_debtors,
            recent_payments=recent_payments,
            recent_receipts=recent_receipts,
            personal_finance_summary=personal_finance_summary
        )
    except Exception as e:
        logger.error(f"Error fetching dashboard data for user {current_user.id}: {str(e)}")
        flash(trans('dashboard_load_error', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('general_bp.home'))
