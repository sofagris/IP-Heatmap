from collections import defaultdict


# EventListener class to handle events and listeners
class EventListener:
    def __init__(self):
        # Dictionary to hold events and corresponding listeners
        self.listeners = defaultdict(list)

    def on_event(self, event_name, listener):
        """
        Register a listener for a specific event.
        :param event_name: str, Name of the event
        :param listener: callable, Function to be called when the event occurs
        """
        self.listeners[event_name].append(listener)

    def trigger_event(self, event_name, data):
        """
        Trigger the listeners for a specific event.
        :param event_name: str, Name of the event
        :param data: Data to pass to the listener functions
        """
        if event_name in self.listeners:
            for listener in self.listeners[event_name]:
                listener(data)


# Global instance of EventListener
Listeners = EventListener()
