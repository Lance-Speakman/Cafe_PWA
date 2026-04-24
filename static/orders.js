// ---------- Checkout Page Logic ----------
const CART_KEY = "cafeFiniganCart";

function loadCart() {
    const stored = localStorage.getItem(CART_KEY);
    return stored ? JSON.parse(stored) : [];
}

function clearCart() {
    localStorage.removeItem(CART_KEY);
}

// Get references to page elements
const rowsBody   = document.getElementById("order-rows");
const totalSpan  = document.getElementById("order-total");
const messageP   = document.getElementById("order-message");
const form       = document.getElementById("order-form");
const nameInput  = document.getElementById("customer-name");
const emailInput = document.getElementById("customer-email");
const timeInput  = document.getElementById("pickup-time");
const messageBox = document.getElementById("formMessage");

function showMessage(message, color = "red") {
    messageBox.textContent = message;
    messageBox.style.color = color;
}
// Load cart and display it
const cart = loadCart();

if (!cart || cart.length === 0) {
    rowsBody.innerHTML = "<tr><td colspan='4'>Your cart is empty.</td></tr>";
    form.style.display = "none";   // hide form if nothing to order
    totalSpan.textContent = "0.00";
} else {
    let total = 0;

    cart.forEach(item => {
        const subtotal = item.Price * item.qty;
        total += subtotal;

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${item.ItemName}</td>
                <td>${item.qty}</td>
                <td>$${item.Price.toFixed(2)}</td>
                <td>$${subtotal.toFixed(2)}</td>
                `;
        rowsBody.appendChild(tr);
    });

    totalSpan.textContent = total.toFixed(2);
}

// When the form is submitted, send the order to Flask
form.addEventListener("submit", event => {
    event.preventDefault();  // stop page reload

    
    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const pickupTime = timeInput.value;
    const items = cart;
    showMessage("");

    if (name.length <= 2 || !/^[A-Za-z]+$/.test(name)) {
        return showMessage("Please enter a valid name (letters only).");
    }

    if (!email.includes("@") || email.length <= 5) {
        return showMessage("Please enter a valid email address.");
    }

    if (items.length === 0) {
        return showMessage("Your cart is empty.");
    }
    const orderData = {
        customerName: name,
        customerEmail: email,
        pickupTime: pickupTime,
        items: items
    };
    
    fetch("http://127.0.0.1:5050/orders", {
        method: "POST",
        headers: { "Content-Type": "application/json",
                    "API-Key": "test321"},
        body: JSON.stringify(orderData)
    })
    .then(res => res.json())
    .then(data => {
        // Store name + time so the Thank-You page can read them
        localStorage.setItem("lastOrderName", nameInput.value.trim());
        localStorage.setItem("lastOrderTime", timeInput.value);

        // Clear the cart
        clearCart();

        // Redirect to Thank-You page
        window.location.href = "thanks.html";
    })
    .catch(() => {
        messageP.textContent = "Could not place order. Is Flask running?";
    });
});

