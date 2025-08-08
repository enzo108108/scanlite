import sqlite3
import pandas as pd


def query_database(db_path="network_data.db"):
    """
    Query the network traffic database and display results.

    Args:
        db_path (str): Path to the SQLite database file.
    """
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)

        # Create a cursor object
        cursor = conn.cursor()

        # Execute a simple query
        query = "SELECT * FROM network_traffic"
        cursor.execute(query)

        # Get column names
        columns = [description[0] for description in cursor.description]

        # Fetch all rows
        rows = cursor.fetchall()

        # Close the connection
        conn.close()

        # Display results
        if not rows:
            print("No data found in the database.")
            return

        # Convert to pandas DataFrame for better display
        df = pd.DataFrame(rows, columns=columns)

        # Display the DataFrame
        print("\nNetwork Traffic Data:")
        print("-" * 80)
        print(df.to_string(index=False))
        print("-" * 80)

        # Print summary statistics
        print("\nSummary Statistics:")
        print(f"Total records: {len(df)}")
        print(f"Unique source MACs: {df['src_mac'].nunique()}")
        print(f"Total bytes sent: {df['total_bytes_sent'].sum():,.0f}")
        print(f"Total bytes received: {df['total_bytes_received'].sum():,.0f}")

    except sqlite3.Error as e:
        print(f"Database error: {str(e)}")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    # You can change the database path if needed
    query_database()
