package adoption

// AppliedMigration names one migration that must already have been applied to a
// database before this service will take ownership of its schema.
type AppliedMigration struct {
	Name string
	// Checksum is the SHA-256 digest, in lower case hexadecimal, of the exact
	// bytes of the migration that was applied. The deployed database records the
	// same digest, so comparing them proves its schema was built by these exact
	// statements and not by a hand-edited variant.
	Checksum string
}

// expectedHistory is the complete, ordered history a database must show to be
// adopted. Adding to it, reordering it, or changing a digest would let a
// database with a different shape pass verification, so it is fixed at the point
// of the migration and never edited afterwards.
var expectedHistory = []AppliedMigration{
	{"20220730111706_initial_migration", "d1f87b41d57f0d103ed42ab66f1026b789e73be71b34c6f9547186c55a9293c8"},
	{"20230225192202_userid_as_uuid", "9c495423b49fca8b3a273dfb137e3a0badb647603f64e9460941afabfeb751a4"},
	{"20230226205054_add_github_account", "3501ea9083abff92b34a046617539b99284665c97ed975e85b773a1a788c72fb"},
	{"20230226205105_add_google_account", "beb2ec27719d8498f85cdf076e10fe631a4d71c8e24d101c54055e2ef655aed7"},
	{"20230608041900_add_developer_account_schema", "e780d421bca7ee6d03aec074dd4ac53679166066fcd8876a86c3e8c95041390e"},
	{
		"20230608213554_rename_developer_account_to_developer_application",
		"f54f60b92ed22a7b9b81f4c66d4c362775f7e9cf866574d5119d0624817f7f77",
	},
	{"20230608232911_add_refresh_token_to_developer_app", "20cfbfbb93983421784b9446b991e7bb138b6814b3a421bc6c4d20a2a7ce5c0b"},
	{
		"20230609031512_remove_unique_id_constraint_on_owner_id_for_dev_app",
		"552e68b552dbae11ffaeb4bc237b9e945e2ca2b8813ac5494e6a4b1b75606958",
	},
	{
		"20230609041532_add_on_delete_cascade_to_all_relationships_to_user",
		"d53deceb066648080ede8939011427962d94a651d86cba9ccf522cf71be9e0dd",
	},
	{
		"20231029025209_add_callback_ur_is_to_developer_applications",
		"0fed65fab484551f88aa32ec9ae0b5b44db7393cf4fffd9538293dbe42b05b7d",
	},
	{"20231029033027_add_callback_uri_uri_field", "83aa847ed7190bef20088346d85ba72642c9cf03ff6008c119dbae499397df4c"},
	{
		"20231104211933_make_callback_uri_unique_for_a_specific_developer_application_id",
		"9d6ca050641efba5a10d035560e7125f2b13655b76517f060f4288460651f97e",
	},
	{"20240415115059_add_test_user", "521863b908059e93da4e6043c1abfdc94d8d47e82f703c8ded99ca379488dd00"},
	{"20240418110549_refactor_password_account", "8ff41b72005517491d8e86ce98e798a907b5884061aed38933a447cee7e16228"},
	{
		"20240421170756_add_autoincrement_for_id_in_password_account",
		"8d0591f990057dc4e115dc30ab9144369dd1f614bcc1db5a36324e6ab38d33d6",
	},
	{"20240429102307_delete_composite_key", "d29b2e92b89fa886653778b18b1fd39f98f9986f5897f34983d303287b88649a"},
	{"20240506151022_add-developer-application-name", "a6bf1451db84630f958007f2dab6b0a2a954ea29ed353a371f2505b4a168e32e"},
}

// ExpectedHistory returns the history a database must show to be adopted.
func ExpectedHistory() []AppliedMigration {
	history := make([]AppliedMigration, len(expectedHistory))
	copy(history, expectedHistory)

	return history
}
