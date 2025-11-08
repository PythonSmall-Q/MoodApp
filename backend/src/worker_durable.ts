// Minimal stub for ChatRoom Durable Object
// The project currently uses D1 (DB) for anonymous chat, but the Cloudflare
// deployment currently has existing Durable Objects that depend on the
// exported class name `ChatRoom`. Removing the exported class causes
// deployment to fail with an error stating the new script does not export
// the class. To allow an immediate deploy while preserving the ability to
// later delete the Durable Object class via a migration, we export a small
// no-op ChatRoom class here.

declare global {
	interface DurableObjectState {}
}

export class ChatRoom {
	state: DurableObjectState;
	constructor(state: DurableObjectState) {
		this.state = state;
	}

	// Minimal fetch handler to satisfy platform requirements. This should not
	// be used by the application — anonymous chat uses D1 now.
	async fetch(_request: Request): Promise<Response> {
		return new Response(JSON.stringify({ ok: true, note: 'ChatRoom stub — DO still present' }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

export default {};
