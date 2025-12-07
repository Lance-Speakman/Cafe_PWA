CREATE TABLE IF NOT EXISTS Customers (
    CustomerID INTEGER PRIMARY KEY AUTOINCREMENT,
    CustomerName TEXT NOT NULL,
    Email TEXT
);

-- What the café actually sells
CREATE TABLE IF NOT EXISTS MenuItems (
    MenuItemID INTEGER PRIMARY KEY AUTOINCREMENT,
    ItemName   TEXT NOT NULL,
    Category   TEXT NOT NULL,   -- e.g. 'Breakfast', 'Drink', 'Snack', 'Lunch'
    Price      REAL NOT NULL
);

-- One order per purchase (linked to a customer)
CREATE TABLE IF NOT EXISTS Orders (
    OrderID    INTEGER PRIMARY KEY AUTOINCREMENT,
    CustomerID INTEGER,
    OrderDate  TEXT,
    FOREIGN KEY (CustomerID) REFERENCES Customers(CustomerID)
);

-- Junction table: items within each order (many-to-many)
CREATE TABLE IF NOT EXISTS OrderItems (
    OrderItemID INTEGER PRIMARY KEY AUTOINCREMENT,
    OrderID     INTEGER,
    MenuItemID  INTEGER,
    Qty         INTEGER DEFAULT 1,
    FOREIGN KEY (OrderID) REFERENCES Orders(OrderID),
    FOREIGN KEY (MenuItemID) REFERENCES MenuItems(MenuItemID)
);