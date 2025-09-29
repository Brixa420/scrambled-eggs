"""
Contact Manager Component

Provides a user interface for managing contacts in the P2P network.
"""

from typing import Callable, Optional

import ipywidgets as widgets
from IPython.display import display


class ContactManager:
    """Contact management UI component."""

    def __init__(self, p2p_manager, on_contact_select: Optional[Callable[[str], None]] = None):
        """Initialize the contact manager.

        Args:
            p2p_manager: Instance of P2PManager
            on_contact_select: Callback when a contact is selected
        """
        self.p2p_manager = p2p_manager
        self.on_contact_select = on_contact_select
        self.contacts = {}
        self._selected_contact = None
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI components."""
        # Contact list
        self.contact_list = widgets.Select(
            options=[],
            description="Contacts:",
            disabled=False,
            layout={"width": "300px", "height": "200px"},
        )

        # Contact details
        self.contact_details = widgets.Output()

        # Action buttons
        self.add_button = widgets.Button(
            description="Add Contact", tooltip="Add a new contact", icon="plus"
        )

        self.remove_button = widgets.Button(
            description="Remove",
            tooltip="Remove selected contact",
            icon="trash",
            button_style="danger",
        )

        self.refresh_button = widgets.Button(description="Refresh", icon="refresh")

        # Search box
        self.search_box = widgets.Text(
            placeholder="Search contacts...", description="Search:", disabled=False
        )

        # Layout
        self.manager = widgets.VBox(
            [
                widgets.HBox([self.search_box, self.refresh_button]),
                widgets.HBox([self.contact_list, self.contact_details]),
                widgets.HBox([self.add_button, self.remove_button]),
            ]
        )

        # Event handlers
        self.contact_list.observe(self._on_contact_selected, names="value")
        self.add_button.on_click(self._on_add_contact)
        self.remove_button.on_click(self._on_remove_contact)
        self.refresh_button.on_click(self.refresh)
        self.search_box.observe(self._on_search, names="value")

        # Initial load
        self.refresh()

    def display(self):
        """Display the contact manager."""
        display(self.manager)

    def refresh(self, _=None):
        """Refresh the contact list."""
        self.contacts = self.p2p_manager.get_contacts()
        self._update_contact_list()

    def _update_contact_list(self, filter_text: str = ""):
        """Update the contact list widget.

        Args:
            filter_text: Text to filter contacts by
        """
        filter_text = filter_text.lower()
        filtered_contacts = {
            contact_id: info
            for contact_id, info in self.contacts.items()
            if (filter_text in contact_id.lower() or filter_text in info.get("name", "").lower())
        }

        # Sort by online status and then by name
        sorted_contacts = sorted(
            filtered_contacts.items(),
            key=lambda x: (not x[1].get("is_online", False), x[1].get("name", x[0])),
        )

        # Update the contact list
        self.contact_list.options = [
            (
                (
                    f"🟢 {info.get('name', contact_id)}"
                    if info.get("is_online", False)
                    else f"⚪ {info.get('name', contact_id)}"
                ),
                contact_id,
            )
            for contact_id, info in sorted_contacts
        ]

    def _on_contact_selected(self, change):
        """Handle contact selection."""
        if not change["new"]:
            return

        contact_id = change["new"]
        self._selected_contact = contact_id
        self._show_contact_details(contact_id)

        # Notify the callback
        if self.on_contact_select:
            self.on_contact_select(contact_id)

    def _show_contact_details(self, contact_id: str):
        """Show details for the selected contact."""
        contact = self.contacts.get(contact_id, {})

        # Clear the details
        self.contact_details.clear_output()

        # Show the details
        with self.contact_details:
            if not contact:
                print("No contact selected")
                return

            print(f"Name: {contact.get('name', 'N/A')}")
            print(f"ID: {contact_id}")
            print(f"Status: {'Online' if contact.get('is_online') else 'Offline'}")
            print(f"Last Seen: {contact.get('last_seen', 'N/A')}")
            print(f"Public Key: {contact.get('public_key', 'N/A')[:30]}...")

    def _on_add_contact(self, _):
        """Handle add contact button click."""
        # Create a dialog to add a new contact
        contact_id_input = widgets.Text(
            placeholder="Enter contact ID or address",
            description="Contact:",
            layout={"width": "300px"},
        )

        name_input = widgets.Text(
            placeholder="Display name (optional)", description="Name:", layout={"width": "300px"}
        )

        add_button = widgets.Button(description="Add")
        cancel_button = widgets.Button(description="Cancel")

        dialog = widgets.VBox(
            [
                widgets.HTML("<h3>Add New Contact</h3>"),
                contact_id_input,
                name_input,
                widgets.HBox([add_button, cancel_button]),
            ]
        )

        def on_add(_):
            contact_id = contact_id_input.value.strip()
            name = name_input.value.strip()

            if not contact_id:
                print("Please enter a contact ID or address")
                return

            # Add the contact
            try:
                self.p2p_manager.add_contact(contact_id, name=name or None)
                self.refresh()
                dialog.close()
            except Exception as e:
                print(f"Error adding contact: {e}")

        def on_cancel(_):
            dialog.close()

        add_button.on_click(on_add)
        cancel_button.on_click(on_cancel)

        # Display the dialog
        display(dialog)

    def _on_remove_contact(self, _):
        """Handle remove contact button click."""
        if not self._selected_contact:
            print("No contact selected")
            return

        # Ask for confirmation
        confirm = input(f"Remove contact {self._selected_contact}? (y/n) ")
        if confirm.lower() == "y":
            self.p2p_manager.remove_contact(self._selected_contact)
            self.refresh()

    def _on_search(self, change):
        """Handle search box changes."""
        self._update_contact_list(change["new"])


def create_contact_manager(p2p_manager, on_contact_select=None):
    """Create and display a contact manager.

    Args:
        p2p_manager: Instance of P2PManager
        on_contact_select: Callback when a contact is selected

    Returns:
        ContactManager: The created contact manager instance
    """
    manager = ContactManager(p2p_manager, on_contact_select)
    manager.display()
    return manager
