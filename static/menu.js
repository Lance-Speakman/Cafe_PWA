console.log("menu.js loaded");
// --------- Simple Cart Storage (localStorage) ---------
const CART_KEY = "cafeFiniganCart";

// Load the cart array from localStorage (or return an empty array)
function loadCart() {
  const stored = localStorage.getItem(CART_KEY);
  return stored ? JSON.parse(stored) : [];
}

// Save the cart array back into localStorage
function saveCart(cart) {
  localStorage.setItem(CART_KEY, JSON.stringify(cart));
}

// Add an item to the cart (or increase quantity if it already exists)
function addToCart(item) {
  const cart = loadCart();

  // Look for an existing entry with the same MenuItemID
  const existing = cart.find(entry => entry.MenuItemID === item.MenuItemID);

  if (existing) {
    existing.qty += 1;              // increase quantity
  } else {
    cart.push({
      MenuItemID: item.MenuItemID,
      ItemName: item.ItemName,
      Price: item.Price,
      qty: 1
    });
  }

  saveCart(cart);
  console.log(`${item.ItemName} added to cart`, cart);
}
// Containers for each category
const breakfastContainer = document.getElementById("menu-breakfast");
const lunchContainer     = document.getElementById("menu-lunch");
const drinksContainer    = document.getElementById("menu-drinks");

// Safety check: are the containers found?
console.log("Containers:", {
  breakfast: breakfastContainer,
  lunch: lunchContainer,
  drinks: drinksContainer
});

// Load menu items from Flask
fetch("http://127.0.0.1:5050/menu")
    .then(res => res.json())
    .then(data => {
        console.log("Menu data from Flask:", data);

        const items = data.menu;  // matches return jsonify({"menu": menu})

        items.forEach(item => {
            let target;

            if (item.Category === "Breakfast") {
                target = breakfastContainer;
            } else if (item.Category === "Lunch") {
                target = lunchContainer;
            } else if (item.Category === "Drinks" || item.Category === "Drink") {
                target = drinksContainer;
            } else {
                target = breakfastContainer; // fallback
            }

            const card = document.createElement("article");
            card.className = "menu-item";
            card.innerHTML = `
                <div class="menu-thumb">
                    <img src="/static/images/${item.FileName}" alt="${item.ItemName}">                    
                </div>
                <div class="menu-info">
                    <h3>${item.ItemName}</h3>
                    <p class="desc">Tasty Café Finigan favourite.</p>
                    <div class="menu-actions">
                        <span class="price">$${Number(item.Price).toFixed(2)}</span>
                        <button class="add-btn">Add</button>
                    </div>
                </div>
            `;
            console.log(item.FileName);
            // Find the Add button inside this card
            const addButton = card.querySelector(".add-btn");

            // When clicked, add this item to the cart in localStorage
            addButton.addEventListener("click", () => {
                addToCart({
                    MenuItemID: item.MenuItemID,
                    ItemName: item.ItemName,
                    Price: item.Price
                });

                console.log(`Added to cart: ${item.ItemName}`);
            });

            if (target) {
                target.appendChild(card);
            }
        });
    })
    .catch(err => {
        console.error("Error loading menu:", err);
        if (breakfastContainer) {
            breakfastContainer.innerHTML = "<p>Unable to load menu items.</p>";
        }
    });