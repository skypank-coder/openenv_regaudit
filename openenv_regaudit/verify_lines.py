from environment.tasks.task1_single_file import CODEBASE, GROUND_TRUTH

lines = CODEBASE['routes.py'].split('\n')
for i, line in enumerate(lines, 1):
    if 'app.logger.info(f"User {user.email} logged in from {request.remote_addr}"' in line:
        print('violation1 line', i, line)
    if "return jsonify({'user': user.to_dict()})" in line:
        print('violation2 return line', i, line)
    if "@app.route('/login', methods=['POST'])" in line:
        print('violation3 decorator line', i, line)
    if '# VIOLATION 2:' in line:
        print('violation2 comment line', i, line)

print('\nGround truth lines:')
for g in GROUND_TRUTH:
    print(g)
