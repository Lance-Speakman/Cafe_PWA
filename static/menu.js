console.log("menu.js loaded");

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
          <img src="../static/images/eggs.jpg" alt="${item.ItemName}">
        </div>
        <div class="menu-info">
          <h3>${item.ItemName}</h3>
          <p class="desc">Tasty Café Finigan favourite.</p>
          <div class="menu-actions">
            <span class="price">$${Number(item.Price).toFixed(2)}</span>
            <button class="add-btn" disabled>Add</button>
          </div>
        </div>
      `;

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