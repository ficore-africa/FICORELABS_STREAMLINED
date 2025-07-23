(function () {
    // Private scope to avoid conflicts
    let currentOrderId = null;
    let offlineData = { orders: [], items: {} };
    let modalElement = null; // Track modal element for cleanup
    const FC_COST = 0.1; // FC cost for creating/submitting order
    const ORDER_COOLDOWN_MINUTES = 5; // Prevent duplicate orders within 5 minutes

    // CSRF Token Setup
    let csrfToken = null;
    function setupCSRF() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            csrfToken = metaTag.getAttribute('content');
        } else {
            console.warn('CSRF token not found in meta tag');
        }
    }

    // Initialize Food Order
    function initFoodOrder() {
        try {
            if (!window.foodOrderTranslations || !window.apiUrls) {
                console.error('Food order translations or API URLs not defined');
                showToast(window.foodOrderTranslations?.general_error || 'Kuskuren tsari: Ba a sami fassarori ko APIs ba', 'danger');
                return;
            }
            if (typeof showToast !== 'function') {
                console.error('showToast function is not defined');
                return;
            }
            if (typeof bootstrap === 'undefined') {
                console.error('Bootstrap JavaScript is not defined');
                showToast('Ana buƙatar Bootstrap JavaScript', 'danger');
                return;
            }

            const root = document.getElementById('food-order-root');
            if (!root) {
                console.error('Food order root element not found');
                showToast(window.foodOrderTranslations?.general_error || 'Kuskure: Ba a sami maƙasudin abinci ba', 'danger');
                return;
            }

            root.innerHTML = `
                <ul class="nav nav-tabs mb-3" id="foodOrderTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="orders-tab" data-bs-toggle="tab" data-bs-target="#orders" type="button" role="tab">${window.foodOrderTranslations?.food_order_create || 'Ƙirƙiri Umurnin Abinci'}</button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="manage-orders-tab" data-bs-toggle="tab" data-bs-target="#manage-orders" type="button" role="tab">${window.foodOrderTranslations?.general_view_all || 'Duba Duk'}</button>
                    </li>
                </ul>
                <div class="tab-content" id="foodOrderTabContent">
                    <div class="tab-pane fade show active" id="orders" role="tabpanel" aria-labelledby="orders-tab">
                        <div class="mb-3">
                            <h6>${window.foodOrderTranslations?.food_order_create || 'Ƙirƙiri Umurnin Abinci'}</h6>
                            <div class="input-group mb-2">
                                <input type="text" class="form-control" id="newOrderName" placeholder="${window.foodOrderTranslations?.food_order_name || 'Sunan Umurni'}">
                                <input type="text" class="form-control" id="newOrderVendor" placeholder="${window.foodOrderTranslations?.food_order_vendor || 'Mai Sayarwa'}">
                            </div>
                            <div class="input-group mb-2">
                                <input type="tel" class="form-control" id="newOrderPhone" placeholder="${window.foodOrderTranslations?.food_order_phone || 'Lambar Wayar'}">
                                <input type="text" class="form-control" id="newOrderLocation" placeholder="${window.foodOrderTranslations?.food_order_location || 'Wurin Isarwa'}">
                                <button class="btn btn-outline-secondary" onclick="foodOrderModule.getUserLocation()">${window.foodOrderTranslations?.food_order_auto_detect || 'Gano Wuri Kai Tsaye'}</button>
                            </div>
                            <div class="alert alert-info">${window.foodOrderTranslations?.food_order_cost_note || `Lura: Ƙirƙiri da ƙaddamar da wannan umurni zai rage ${FC_COST} FC daga ma'auni naka.`}</div>
                            <button class="btn btn-primary" onclick="foodOrderModule.createFoodOrder()">${window.foodOrderTranslations?.food_order_create || 'Ƙirƙira'}</button>
                        </div>
                        <div id="foodOrders"></div>
                        <div id="foodOrderItems" class="mt-3"></div>
                        <div class="mt-3">
                            <h6>${window.foodOrderTranslations?.food_order_add_item || 'Ƙara Abu'}</h6>
                            <div class="input-group mb-2">
                                <input type="text" class="form-control" id="newOrderItemName" placeholder="${window.foodOrderTranslations?.food_order_item_name || 'Sunan Abu'}">
                                <input type="number" class="form-control" id="newOrderItemQuantity" placeholder="${window.foodOrderTranslations?.food_order_quantity || 'Yawa'}" min="1">
                                <input type="number" class="form-control" id="newOrderItemPrice" placeholder="${window.foodOrderTranslations?.food_order_price || 'Farashi'}" min="0" step="0.01">
                            </div>
                            <div class="input-group mb-2">
                                <input type="text" class="form-control" id="newOrderItemNotes" placeholder="${window.foodOrderTranslations?.food_order_item_notes || 'Bayanan Abu (misali, Babu Barkono)'}">
                                <button class="btn btn-primary" onclick="foodOrderModule.addFoodOrderItem()">${window.foodOrderTranslations?.food_order_add || 'Ƙara'}</button>
                            </div>
                        </div>
                    </div>
                    <div class="tab-pane fade" id="manage-orders" role="tabpanel" aria-labelledby="manage-orders-tab">
                        <div class="mb-3">
                            <h6>${window.foodOrderTranslations?.general_view_all || 'Duba Duk'}</h6>
                            <div id="manageFoodOrders"></div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="successModal" tabindex="-1" aria-labelledby="successModalLabel" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="successModalLabel">${window.foodOrderTranslations?.food_order_success_title || 'An Tura Umurni'}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                ${window.foodOrderTranslations?.food_order_success_message || 'An tura umurnin ka. Mai sayarwa zai kira ka nan ba da jimawa ba.'}
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-primary" data-bs-dismiss="modal">${window.foodOrderTranslations?.food_order_ok || 'To'}</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Initialize Bootstrap tabs
            const tabEl = document.querySelector('#foodOrderTabs');
            if (tabEl) {
                new bootstrap.Tab(tabEl.querySelector('.nav-link.active')).show();
            }

            // Store modal element and attach cleanup listener
            modalElement = document.getElementById('foodOrderModal');
            if (modalElement) {
                modalElement.addEventListener('hidden.bs.modal', cleanupModal);
            }

            // Load initial data
            loadFoodOrders();
            loadManageOrders();
        } catch (error) {
            console.error('Error initializing food order:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    // Clean up modal state when hidden
    function cleanupModal() {
        try {
            currentOrderId = null; // Reset current order
            const foodOrdersEl = document.getElementById('foodOrders');
            const foodOrderItemsEl = document.getElementById('foodOrderItems');
            const manageOrdersEl = document.getElementById('manageFoodOrders');
            if (foodOrdersEl) foodOrdersEl.innerHTML = '';
            if (foodOrderItemsEl) foodOrderItemsEl.innerHTML = '';
            if (manageOrdersEl) manageOrdersEl.innerHTML = '';
            // Reinitialize Bootstrap tabs instead of cloning
            const tabEl = document.querySelector('#foodOrderTabs');
            if (tabEl) {
                const activeTab = tabEl.querySelector('.nav-link.active');
                if (activeTab) {
                    new bootstrap.Tab(activeTab).show();
                }
            }
            // Ensure body scroll is restored
            document.body.classList.remove('modal-open');
            const modalBackdrop = document.querySelector('.modal-backdrop');
            if (modalBackdrop) {
                modalBackdrop.remove();
            }
        } catch (error) {
            console.error('Error during modal cleanup:', error);
        }
    }

    // Fetch with CSRF token
    async function fetchWithCSRF(url, options = {}) {
        try {
            const headers = {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
                ...options.headers
            };
            const response = await fetch(url, { ...options, headers });
            return response;
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }

    // Get user location
    async function getUserLocation() {
        try {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(
                    async (position) => {
                        const { latitude, longitude } = position.coords;
                        const location = `${latitude},${longitude}`;
                        document.getElementById('newOrderLocation').value = location;
                        // Fetch nearest vendor based on location
                        const response = await fetchWithCSRF(`${window.apiUrls.getNearestVendor}?location=${location}`);
                        const data = await response.json();
                        if (data.vendor) {
                            document.getElementById('newOrderVendor').value = data.vendor;
                        }
                    },
                    (error) => {
                        console.error('Error getting location:', error);
                        showToast(window.foodOrderTranslations?.food_order_location_error || 'Ba za a iya gano wurin kai tsaye ba. Da fatan za a shigar da hannu.', 'warning');
                    }
                );
            } else {
                showToast(window.foodOrderTranslations?.food_order_geolocation_unsupported || 'Binciken wurin ba ya da goyon baya a wannan burauza.', 'warning');
            }
        } catch (error) {
            console.error('Error in getUserLocation:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    // Check for recent orders to prevent duplicates
    function canCreateOrder() {
        const lastOrderTime = localStorage.getItem('lastOrderTime');
        if (!lastOrderTime) return true;
        const lastTime = new Date(lastOrderTime);
        const now = new Date();
        const diffMinutes = (now - lastTime) / 1000 / 60;
        return diffMinutes >= ORDER_COOLDOWN_MINUTES;
    }

    // Food Order Functions
    async function loadFoodOrders() {
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrders);
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const orders = await response.json();
            offlineData.orders = orders;
            localStorage.setItem('foodOrders', JSON.stringify(orders));
            renderFoodOrders(orders);
        } catch (error) {
            console.error('Error loading food orders:', error);
            renderFoodOrders([]);
        }
    }

    function renderFoodOrders(orders) {
        const foodOrdersEl = document.getElementById('foodOrders');
        if (!foodOrdersEl) return;
        if (orders && orders.length > 0) {
            foodOrdersEl.innerHTML = orders.map(order => `
                <div class="food-order-item">
                    <span class="fw-semibold">${order.name} (${order.vendor})</span>
                    <div>
                        <span class="text-muted">${window.foodOrderTranslations?.food_order_total || 'Jimla'}: ${format_currency(order.total_cost)}</span>
                        <button class="btn btn-sm btn-outline-primary ms-2" onclick="foodOrderModule.loadFoodOrderItems('${order.id}')">${window.foodOrderTranslations?.general_view_all || 'Duba Duk'}</button>
                        <button class="btn btn-sm btn-outline-success ms-2" onclick="foodOrderModule.reorder('${order.id}')">${window.foodOrderTranslations?.food_order_reorder || 'Sake Umurni'}</button>
                    </div>
                </div>
            `).join('');
            if (!currentOrderId && orders[0]) {
                loadFoodOrderItems(orders[0].id);
            }
        } else {
            foodOrdersEl.innerHTML = `<div class="text-muted">${window.foodOrderTranslations?.no_orders || 'Ba a sami umurnin abinci ba'}</div>`;
        }
    }

    async function loadManageOrders() {
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrders);
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const orders = await response.json();
            offlineData.orders = orders;
            localStorage.setItem('foodOrders', JSON.stringify(orders));
            renderManageOrders(orders);
        } catch (error) {
            console.error('Error loading food orders for management:', error);
            renderManageOrders([]);
        }
    }

    function renderManageOrders(orders) {
        const manageOrdersEl = document.getElementById('manageFoodOrders');
        if (!manageOrdersEl) return;
        if (orders && orders.length > 0) {
            manageOrdersEl.innerHTML = orders.map(order => `
                <div class="food-order-item">
                    <span class="fw-semibold">${order.name} (${order.vendor})</span>
                    <div>
                        <span class="text-muted">${window.foodOrderTranslations?.food_order_total || 'Jimla'}: ${format_currency(order.total_cost)}</span>
                        <button class="btn btn-sm btn-outline-danger ms-2" onclick="foodOrderModule.deleteFoodOrder('${order.id}', '${order.name}')">${window.foodOrderTranslations?.food_order_delete || 'Goge'}</button>
                        <button class="btn btn-sm btn-outline-success ms-2" onclick="foodOrderModule.reorder('${order.id}')">${window.foodOrderTranslations?.food_order_reorder || 'Sake Umurni'}</button>
                    </div>
                </div>
            `).join('');
        } else {
            manageOrdersEl.innerHTML = `<div class="text-muted">${window.foodOrderTranslations?.no_orders || 'Ba a sami umurnin abinci ba'}</div>`;
        }
    }

    async function deleteFoodOrder(orderId, orderName) {
        if (!confirm(`${window.foodOrderTranslations?.food_order_confirm_delete || 'Goge umurnin abinci'} "${orderName}"?`)) {
            return;
        }
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrders + `/${orderId}`, {
                method: 'DELETE'
            });
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (data.error) {
                showToast(data.error, 'danger');
            } else {
                showToast(window.foodOrderTranslations?.food_order_deleted || 'An goge umurnin abinci', 'success');
                if (currentOrderId === orderId) {
                    currentOrderId = null;
                    const foodOrderItemsEl = document.getElementById('foodOrderItems');
                    if (foodOrderItemsEl) foodOrderItemsEl.innerHTML = '';
                }
                loadFoodOrders();
                loadManageOrders();
                if (typeof loadFinancialSummary === 'function') {
                    loadFinancialSummary();
                }
            }
        } catch (error) {
            console.error('Error deleting food order:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    async function loadFoodOrderItems(orderId) {
        currentOrderId = orderId;
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrderItems.replace('{order_id}', orderId));
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const items = await response.json();
            offlineData.items[orderId] = items;
            localStorage.setItem('foodOrderItems', JSON.stringify(offlineData.items));
            renderFoodOrderItems(items);
        } catch (error) {
            console.error('Error loading food order items:', error);
            renderFoodOrderItems([]);
        }
    }

    function renderFoodOrderItems(items) {
        const foodOrderItemsEl = document.getElementById('foodOrderItems');
        if (!foodOrderItemsEl) return;
        if (items && items.length > 0) {
            foodOrderItemsEl.innerHTML = items.map(item => `
                <div class="food-order-item">
                    <span class="fw-semibold">${item.name}</span>
                    <div class="d-flex align-items-center gap-2">
                        <input type="number" class="form-control" value="${item.quantity}" min="1" onchange="foodOrderModule.updateFoodOrderItem('${item.item_id}', 'quantity', this.value)">
                        <input type="number" class="form-control" value="${item.price}" min="0" step="0.01" onchange="foodOrderModule.updateFoodOrderItem('${item.item_id}', 'price', this.value)">
                        <input type="text" class="form-control" value="${item.notes || ''}" placeholder="${window.foodOrderTranslations?.food_order_item_notes || 'Bayanan Abu'}" onchange="foodOrderModule.updateFoodOrderItem('${item.item_id}', 'notes', this.value)">
                    </div>
                </div>
            `).join('');
        } else {
            foodOrderItemsEl.innerHTML = `<div class="text-muted">${window.foodOrderTranslations?.no_items || 'Babu abubuwa a cikin wannan umurni'}</div>`;
        }
    }

    async function createFoodOrder() {
        if (!canCreateOrder()) {
            showToast(window.foodOrderTranslations?.food_order_duplicate || `Da fatan za a jira mintuna ${ORDER_COOLDOWN_MINUTES} kafin ƙirƙirar wani umurni`, 'warning');
            return;
        }
        const name = document.getElementById('newOrderName').value;
        const vendor = document.getElementById('newOrderVendor').value;
        const phone = document.getElementById('newOrderPhone').value;
        const location = document.getElementById('newOrderLocation').value;
        if (!name || !vendor || !phone || !location) {
            showToast(window.foodOrderTranslations?.general_please_provide || 'Da fatan za a ba da duk filayen da ake buƙata', 'warning');
            return;
        }
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrders, {
                method: 'POST',
                body: JSON.stringify({ name, vendor, phone, location })
            });
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (data.error) {
                showToast(data.error, 'danger');
            } else {
                localStorage.setItem('lastOrderTime', new Date().toISOString());
                showSuccessModal();
                document.getElementById('newOrderName').value = '';
                document.getElementById('newOrderVendor').value = '';
                document.getElementById('newOrderPhone').value = '';
                document.getElementById('newOrderLocation').value = '';
                loadFoodOrders();
                loadManageOrders();
                if (typeof loadFinancialSummary === 'function') {
                    loadFinancialSummary();
                }
            }
        } catch (error) {
            console.error('Error creating food order:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    async function addFoodOrderItem() {
        if (!currentOrderId) {
            showToast(window.foodOrderTranslations?.general_select_order || 'Da fatan za a zaɓi umurni', 'warning');
            return;
        }
        const name = document.getElementById('newOrderItemName').value;
        const quantity = document.getElementById('newOrderItemQuantity').value;
        const price = document.getElementById('newOrderItemPrice').value;
        const notes = document.getElementById('newOrderItemNotes').value;
        if (!name || !quantity || !price) {
            showToast(window.foodOrderTranslations?.general_please_provide || 'Da fatan za a ba da duk filayen da ake buƙata', 'warning');
            return;
        }
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrderItems.replace('{order_id}', currentOrderId), {
                method: 'POST',
                body: JSON.stringify({ name, quantity, price, notes })
            });
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (data.error) {
                showToast(data.error, 'danger');
            } else {
                showToast(window.foodOrderTranslations?.item_added || 'An ƙara abu ga umurni', 'success');
                document.getElementById('newOrderItemName').value = '';
                document.getElementById('newOrderItemQuantity').value = '';
                document.getElementById('newOrderItemPrice').value = '';
                document.getElementById('newOrderItemNotes').value = '';
                loadFoodOrderItems(currentOrderId);
                if (typeof loadFinancialSummary === 'function') {
                    loadFinancialSummary();
                }
            }
        } catch (error) {
            console.error('Error adding food order item:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    async function updateFoodOrderItem(itemId, field, value) {
        try {
            const response = await fetchWithCSRF(window.apiUrls.manageFoodOrderItems.replace('{order_id}', currentOrderId), {
                method: 'PUT',
                body: JSON.stringify({ item_id: itemId, [field]: value })
            });
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (data.error) {
                showToast(data.error, 'danger');
            } else {
                showToast(window.foodOrderTranslations?.item_updated || 'An sabunta abu', 'success');
                loadFoodOrderItems(currentOrderId);
                if (typeof loadFinancialSummary === 'function') {
                    loadFinancialSummary();
                }
            }
        } catch (error) {
            console.error('Error updating food order item:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    async function reorder(orderId) {
        try {
            const response = await fetchWithCSRF(window.apiUrls.reorderFoodOrder.replace('{order_id}', orderId), {
                method: 'POST'
            });
            if (response.status === 403) {
                showToast(window.foodOrderTranslations?.insufficient_credits || 'Rashin isassun ƙididdiga', 'error');
                throw new Error('Unauthorized');
            }
            const data = await response.json();
            if (data.error) {
                showToast(data.error, 'danger');
            } else {
                localStorage.setItem('lastOrderTime', new Date().toISOString());
                showSuccessModal();
                loadFoodOrders();
                loadManageOrders();
                if (typeof loadFinancialSummary === 'function') {
                    loadFinancialSummary();
                }
            }
        } catch (error) {
            console.error('Error reordering food order:', error);
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    function showSuccessModal() {
        const successModalEl = document.getElementById('successModal');
        if (successModalEl && typeof bootstrap !== 'undefined') {
            const successModal = new bootstrap.Modal(successModalEl);
            successModal.show();
        } else {
            console.error('Success modal element or Bootstrap not found');
            showToast(window.foodOrderTranslations?.general_error || 'Kuskure ya faru', 'danger');
        }
    }

    function loadOfflineData() {
        const cachedOrders = localStorage.getItem('foodOrders');
        const cachedItems = localStorage.getItem('foodOrderItems');
        if (cachedOrders) {
            offlineData.orders = JSON.parse(cachedOrders);
            renderFoodOrders(offlineData.orders);
            renderManageOrders(offlineData.orders);
        }
        if (cachedItems) {
            offlineData.items = JSON.parse(cachedItems);
            if (currentOrderId && offlineData.items[currentOrderId]) {
                renderFoodOrderItems(offlineData.items[currentOrderId]);
            }
        }
    }

    function format_currency(value) {
        if (!value && value !== 0) return '₦0.00';
        value = parseFloat(value);
        if (isNaN(value)) return '₦0.00';
        return value.toLocaleString('en-NG', { style: 'currency', currency: 'NGN' });
    }

    function formatTimeAgo(dateStr) {
        const now = new Date();
        const date = new Date(dateStr);
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) return window.foodOrderTranslations?.just_now || 'Yanzu';
        if (diffMins < 60) return `${diffMins} ${window.foodOrderTranslations?.minutes_ago || 'mintuna da suka wuce'}`;
        if (diffHours < 24) return `${diffHours} ${window.foodOrderTranslations?.hours_ago || 'awanni da suka wuce'}`;
        return `${diffDays} ${window.foodOrderTranslations?.days_ago || 'kwanaki da suka wuce'}`;
    }

    // Expose functions to the global scope with a namespace
    window.foodOrderModule = {
        initFoodOrder,
        createFoodOrder,
        addFoodOrderItem,
        updateFoodOrderItem,
        loadFoodOrderItems,
        deleteFoodOrder,
        getUserLocation,
        reorder
    };

    // Initialize CSRF token
    setupCSRF();
})();
