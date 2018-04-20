from flask import Flask, render_template
import constants as C
app = Flask(__name__)


@app.route('/', methods=['GET'])
def bgp_index():
    source_asn = C._DEFAULT_ASN
    return render_template('bgp.html', **locals())


if __name__ == '__main__':
    app.run(debug=True)
