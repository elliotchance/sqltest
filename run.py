import yaml
import cgi

features_file = open("standards/ISO_IEC_9075-2-2016-E_Foundation/features.yml", "r")
features = yaml.load(features_file)

with open("report.html", "w") as report_file:
    report_file.write("<html><head><title>SQL Conformance</title><body>")

    report_file.write("<h1>Mandatory Features (%d)</h1>" % len(features['mandatory']))
    report_file.write("<table border='1' cellpadding='3' width='100%'>")

    i = 1
    for feature_id in sorted(features['mandatory']):
        feature_name = features['mandatory'][feature_id]
        report_file.write("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (i, feature_id, cgi.escape(feature_name)))
        i += 1

    report_file.write("</table>")

    report_file.write("<h1>Optional Features (%d)</h1>" % len(features['optional']))
    report_file.write("<table border='1' cellpadding='3' width='100%'>")

    for feature_id in sorted(features['optional']):
        feature_name = features['optional'][feature_id]
        report_file.write("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (i, feature_id, cgi.escape(feature_name)))
        i += 1

    report_file.write("</table>")

    report_file.write("</body></html>")
