import json
import os
from typing import Dict, Any, List
from jinja2 import Template
from shockwave.tests.auth_matrix import AuthMatrix, FieldAccess

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ShockWave Authorization Matrix</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #58a6ff;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }
        .meta {
            color: #8b949e;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        .filters {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
        }
        input[type="text"] {
            background-color: #161b22;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 8px 12px;
            border-radius: 6px;
            width: 300px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        th {
            background-color: #21262d;
            color: #c9d1d9;
            cursor: pointer;
        }
        th:hover {
            background-color: #30363d;
        }
        tr:hover {
            background-color: #21262d;
        }
        .accessible {
            background-color: rgba(46, 160, 67, 0.15);
            color: #3fb950;
            font-weight: bold;
            border: 1px solid rgba(46, 160, 67, 0.4);
            border-radius: 4px;
            padding: 4px 8px;
            display: inline-block;
        }
        .blocked {
            background-color: rgba(248, 81, 73, 0.15);
            color: #f85149;
            font-weight: bold;
            border: 1px solid rgba(248, 81, 73, 0.4);
            border-radius: 4px;
            padding: 4px 8px;
            display: inline-block;
        }
        .error {
            background-color: rgba(210, 153, 34, 0.15);
            color: #d29922;
            font-weight: bold;
            border: 1px solid rgba(210, 153, 34, 0.4);
            border-radius: 4px;
            padding: 4px 8px;
            display: inline-block;
        }
        .untested {
            background-color: rgba(139, 148, 158, 0.15);
            color: #8b949e;
            border: 1px solid rgba(139, 148, 158, 0.4);
            border-radius: 4px;
            padding: 4px 8px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ShockWave — GraphQL Authorization Matrix</h1>
        <div class="meta">
            <strong>Schema Hash:</strong> {{ matrix.schema_hash }}<br>
            <strong>Scan Timestamp:</strong> {{ matrix.scan_timestamp }}
        </div>
        
        <div class="filters">
            <input type="text" id="search" placeholder="Filter by field path (e.g. Query.user)..." onkeyup="filterTable()">
        </div>

        <table id="matrixTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Field Path</th>
                    {% for ctx in matrix.auth_contexts %}
                        <th onclick="sortTable({{ loop.index }})">{{ ctx }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for field_path, accesses in matrix.fields.items() %}
                <tr>
                    <td><strong>{{ field_path }}</strong></td>
                    {% for ctx in matrix.auth_contexts %}
                        <td>
                            {% set val = accesses.get(ctx, "untested") %}
                            <span class="{{ val }}">{{ val }}</span>
                        </td>
                    {% endfor %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        function filterTable() {
            var input = document.getElementById("search");
            var filter = input.value.toUpperCase();
            var table = document.getElementById("matrixTable");
            var tr = table.getElementsByTagName("tr");

            for (var i = 1; i < tr.length; i++) {
                var td = tr[i].getElementsByTagName("td")[0];
                if (td) {
                    var txtValue = td.textContent || td.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    } else {
                        tr[i].style.display = "none";
                    }
                }
            }
        }

        function sortTable(n) {
            var table = document.getElementById("matrixTable");
            var rows = table.rows;
            var switching = true;
            var dir = "asc";
            var switchcount = 0;

            while (switching) {
                switching = false;
                for (var i = 1; i < (rows.length - 1); i++) {
                    var shouldSwitch = false;
                    var x = rows[i].getElementsByTagName("TD")[n];
                    var y = rows[i + 1].getElementsByTagName("TD")[n];

                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir == "desc") {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") {
                        dir = "desc";
                        switching = true;
                    }
                }
            }
        }
    </script>
</body>
</html>
"""

def write_auth_matrix(matrix: AuthMatrix, output_dir: str) -> None:
    """Writes JSON and self-contained HTML representation of authorization matrix."""
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Write JSON
    json_path = os.path.join(output_dir, "auth_matrix.json")
    matrix_data = {
        "schema_hash": matrix.schema_hash,
        "scan_timestamp": matrix.scan_timestamp,
        "auth_contexts": matrix.auth_contexts,
        "fields": {k: {role: val.value for role, val in v.items()} for k, v in matrix.fields.items()}
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(matrix_data, f, indent=2)

    # 2. Write HTML
    html_path = os.path.join(output_dir, "auth_matrix.html")
    template = Template(HTML_TEMPLATE)
    html_content = template.render(matrix=matrix_data)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
