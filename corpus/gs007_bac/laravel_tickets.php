<?php
/**
 * Test: Laravel — find without auth, status update, add subscriber.
 *
 * Meta-inspired: ticket operations without permission checks.
 */

class TicketController extends Controller
{
    // VULN: find without auth check
    public function show($id)
    {
        $ticket = Ticket::find($id);  // GS007: Laravel find
        return response()->json($ticket);
    }

    // VULN: Status update from request without ownership check
    public function updateStatus(Request $request, $id)
    {
        $ticket = Ticket::find($id);
        $ticket->status = $request->input('status');  // GS007: status mutation
        $ticket->save();
    }

    // VULN: Add subscriber without permission check
    public function addSubscriber(Request $request, $id)
    {
        $ticket = Ticket::find($id);
        $ticket->add_subscriber($request->user());  // GS007: subscriber operation
    }
}
