<?php
/*
Plugin Name: Private Page Access
Description: Ermöglicht den Zugriff auf private Seiten über einen speziellen Link mit Token.
Version: 1.5
Author: Dein Name
*/

// Token generieren mit benutzerdefinierter Ablaufzeit
function generate_token($page_id, $expiry_hours) {
    $expiry_time = time() + ($expiry_hours * 3600); // Ablaufzeit in Sekunden umrechnen
    return bin2hex(openssl_random_pseudo_bytes(16)) . '|' . $page_id . '|' . $expiry_time;
}

// Token validieren mit Ablaufzeit
function validate_token($token) {
    list($token_part, $page_id, $expiry_time) = explode('|', $token);
    if (time() > $expiry_time) {
        return false; // Token ist abgelaufen
    }
    return ctype_xdigit($token_part) ? $page_id : false;
}

// Token-Logging-Funktion
function log_token_use($token) {
    $logs = get_option('private_page_token_logs', []);
    $logs[] = ['token' => $token, 'timestamp' => time(), 'ip' => $_SERVER['REMOTE_ADDR']];
    update_option('private_page_token_logs', $logs);
}

// Zugriff auf private Seite erlauben
function allow_private_page_access($query) {
    if (isset($_GET['token'])) {
        $page_id = validate_token($_GET['token']);
        if ($page_id && $query->is_main_query() && !$query->is_admin() && $query->queried_object_id == $page_id) {
            // Loggen und Benachrichtigung senden
            log_token_use($_GET['token']);
            wp_mail(get_option('admin_email'), 'Token verwendet', 'Ein Token wurde verwendet für Seite ID ' . $page_id);

            // Seite auf öffentlich setzen, um Zugriff zu gewähren
            add_filter('posts_results', function($posts) use ($page_id) {
                if (!empty($posts) && $posts[0]->ID == $page_id) {
                    $posts[0]->post_status = 'publish';
                }
                return $posts;
            });
        }
    }
}
add_action('pre_get_posts', 'allow_private_page_access');

// Admin-Menü hinzufügen
function private_page_access_menu() {
    add_menu_page('Private Page Access', 'Private Page Access', 'manage_options', 'private-page-access', 'private_page_access_page');
}
add_action('admin_menu', 'private_page_access_menu');

// Token speichern
function save_token($page_id, $token) {
    $tokens = get_option('private_page_tokens', []);
    $tokens[$page_id] = $token;
    update_option('private_page_tokens', $tokens);
}

// Token löschen
function delete_token($page_id) {
    $tokens = get_option('private_page_tokens', []);
    if (isset($tokens[$page_id])) {
        unset($tokens[$page_id]);
        update_option('private_page_tokens', $tokens);
    }
}

// Admin-Seite rendern
function private_page_access_page() {
    if (isset($_POST['page_id']) && isset($_POST['expiry_hours'])) {
        $page_id = intval($_POST['page_id']);
        $expiry_hours = intval($_POST['expiry_hours']);
        $token = generate_token($page_id, $expiry_hours);
        save_token($page_id, $token);
        $generated_url = get_permalink($page_id) . '?token=' . $token;
        echo '<div id="message" class="updated notice is-dismissible"><p>Token generiert: <code>' . $token . '</code></p>';
        echo '<p>URL: <code id="generated-url">' . $generated_url . '</code></p>';
        echo '<button class="button" onclick="copyToClipboard()">URL kopieren</button></div>';
    }

    if (isset($_POST['delete_page_id'])) {
        $page_id = intval($_POST['delete_page_id']);
        delete_token($page_id);
        echo '<div id="message" class="updated notice is-dismissible"><p>Freigabe für Seite mit ID ' . $page_id . ' wurde zurückgenommen.</p></div>';
    }

    $tokens = get_option('private_page_tokens', []);
    ?>
    <div class="wrap">
        <h1>Private Page Access</h1>
        <form method="post" style="margin-bottom: 20px;">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="page_id">Seite auswählen:</label></th>
                    <td>
                        <select name="page_id" id="page_id" required>
                            <?php
                            $pages = get_pages(['post_status' => 'private']);
                            foreach ($pages as $page) {
                                echo '<option value="' . $page->ID . '">' . $page->post_title . ' (ID: ' . $page->ID . ')</option>';
                            }
                            ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="expiry_hours">Ablaufzeit (Stunden):</label></th>
                    <td>
                        <input type="number" name="expiry_hours" id="expiry_hours" required>
                    </td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" value="Token generieren" class="button-primary">
            </p>
        </form>

        <h2>Freigegebene Seiten</h2>
        <table class="widefat fixed">
            <thead>
                <tr>
                    <th>Seiten-ID</th>
                    <th>Token</th>
                    <th>URL</th>
                    <th>Aktionen</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tokens as $page_id => $token): ?>
                    <tr>
                        <td><?php echo $page_id; ?></td>
                        <td><?php echo $token; ?></td>
                        <td><?php echo get_permalink($page_id) . '?token=' . $token; ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <input type="hidden" name="delete_page_id" value="<?php echo $page_id; ?>">
                                <input type="submit" value="Freigabe zurücknehmen" class="button">
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <h2>Token-Log</h2>
        <table class="widefat fixed">
            <thead>
                <tr>
                    <th>Token</th>
                    <th>Verwendet am</th>
                    <th>IP-Adresse</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $logs = get_option('private_page_token_logs', []);
                foreach ($logs as $log) {
                    echo '<tr>';
                    echo '<td>' . esc_html($log['token']) . '</td>';
                    echo '<td>' . date('Y-m-d H:i:s', $log['timestamp']) . '</td>';
                    echo '<td>' . esc_html($log['ip']) . '</td>';
                    echo '</tr>';
                }
                ?>
            </tbody>
        </table>
    </div>
    <script>
        function copyToClipboard() {
            const urlField = document.getElementById('generated-url');
            const range = document.createRange();
            range.selectNode(urlField);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            window.getSelection().removeAllRanges();
            alert('URL wurde in die Zwischenablage kopiert!');
        }
    </script>
    <style>
        .form-table th {
            padding: 10px 10px 10px 0;
        }
        .form-table td {
            padding: 10px 0;
        }
        .form-table select, .form-table input[type="number"] {
            width: 100%;
            max-width: 300px;
        }
        .button-primary {
            margin-top: 10px;
        }
        .widefat th, .widefat td {
            padding: 8px 10px;
        }
        .widefat thead th {
            background-color: #f1f1f1;
        }
    </style>
    <?php
}
?>
