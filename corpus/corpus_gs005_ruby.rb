# SQLi test corpus for GS005 — Ruby patterns.
# Every uncommented line should be detected.

# ═══ POSITIVE — Rails ══════════════════════════════════════════════════
User.where("name = '#{params[:name]}' AND active = 1")
User.find_by_sql("SELECT * FROM users WHERE email = '#{email}'")
ActiveRecord::Base.connection.execute("SELECT * FROM logs WHERE id = #{log_id}")
User.select_all("SELECT * FROM products WHERE sku = '#{sku}'")
