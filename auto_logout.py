import threading

class AutoLogout:
    def __init__(self, timeout_sec, logout_callback):
        self.timeout_sec = timeout_sec
        self.logout_callback = logout_callback
        self.timer = None

    def reset_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(self.timeout_sec, self.logout_callback)
        self.timer.start()

    def stop_timer(self):
        if self.timer:
            self.timer.cancel()
