# Manager-service
decides what each user or role may do in each service, and approves things such as purchase bills before they proceed.
now this is my new service to the erp platform  which is manager service this servie manages all the erp platform 
2. Roles and permissions list

A table of role → permissions for the first version, for example:

Role	Can do
admin	everything, including managing roles
manager	approve bills, view all services
purchaser	create bills, view catalog and parties
inventory_clerk	adjust and receive stock
accountant	view approved bills, create payables

What approval thresholds apply? For example, under ₹50,000 needs one manager, and above that needs two levels.
Can anyone with the manager role approve, or only certain managers?
Can the requester approve their own bill? My default is no.
Can a rejected bill be resubmitted, or does it need a new bill?
Does a pending request expire?

Also define the bill status lifecycle, which Purchasing must follow: draft → pending_approval → approved | rejected, and then what happens after approved (paid, received).