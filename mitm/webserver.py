import flask
app = flask.Flask(__name__)

@app.route('/')
def index():
    return 'Success!'

@app.route('/downloads/RemoteMouse.exe')
def exe():
    return flask.send_file('RemoteMouse.exe')

@app.route('/autoupdater/AutoUpdater.NET_AppCast_RM.xml')
def xml():
    return flask.send_file('AutoUpdater.NET_AppCast_RM.xml')


@app.route('/autoupdater/releasenotes_rm.html')
def changelog():
    return flask.render_template('changelog.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)