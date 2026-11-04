# Records docs/assets/quickstart-demo.gif for the README.
# Run `vhs quickstart-demo.tape` from a scratch directory that holds a
# tenkaictl binary and a copy of examples/hello-local, then copy demo.gif here.
Output demo.gif
Set Shell bash
Set FontSize 14
Set Width 1500
Set Height 660
Set Padding 18
Set TypingSpeed 25ms
Set Theme { "background": "#000000", "foreground": "#ffffff", "black": "#000000", "red": "#ff5f5f", "green": "#5fff87", "yellow": "#ffd75f", "blue": "#5fafff", "magenta": "#d787ff", "cyan": "#5fd7ff", "white": "#ffffff", "brightBlack": "#808080", "brightRed": "#ff8787", "brightGreen": "#87ffaf", "brightYellow": "#ffff87", "brightBlue": "#87d7ff", "brightMagenta": "#ffafff", "brightCyan": "#87ffff", "brightWhite": "#ffffff", "cursor": "#ffffff", "selection": "#444444" }
Hide
Type "export PS1='$ ' TENKAI_MANAGEMENT_TOKEN=tenkai-local-management && clear" Enter
Sleep 1s
Show
Type "./tenkaictl init" Enter Sleep 1.2s
Type "./tenkaictl publish examples/hello-local/tenkai.toml --allow-unsigned-development" Enter Sleep 600ms
Type "./tenkaictl promote hello-local@0.1.0 stable && ./tenkaictl env subscribe local hello-local=stable" Enter Sleep 800ms
Type "PLAN=$(./tenkaictl plan | awk '/^plan id:/ {print $3}')" Enter Sleep 400ms
Type "./tenkaictl apply $PLAN --allow-unapproved-development --development-reason demo" Enter Sleep 1.5s
Type "# ship 0.2.0, whose health probe fails" Enter Sleep 600ms
Type "./tenkaictl publish examples/hello-local/broken.toml --allow-unsigned-development && ./tenkaictl promote hello-local@0.2.0 stable" Enter Sleep 800ms
Type "PLAN=$(./tenkaictl plan | awk '/^plan id:/ {print $3}')" Enter Sleep 400ms
Type "./tenkaictl apply $PLAN --allow-unapproved-development --development-reason demo" Enter Sleep 2s
Type "./tenkaictl status" Enter Sleep 3.5s
