----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

Organizer = {}

Organizer.Organizers = 1
Organizer.Undresses = 1
Organizer.Restocks = 1
Organizer.Buys = 1
Organizer.Sells = 1
Organizer.Scavengers = 1

Organizer.ActiveOrganizer = 1
Organizer.ActiveUndress = 1
Organizer.ActiveRestock = 1
Organizer.ActiveBuy = 1
Organizer.ActiveSell = 1
Organizer.ActiveScavenger = 1

Organizer.Organizers_Items = {} -- number of items of every organizer
Organizer.Undresses_Items = {}
Organizer.Restocks_Items = {}
Organizer.Buys_Items = {}
Organizer.Sells_Items = {}
Organizer.Scavengers_Items = {}

Organizer.Organizers_Desc = {} -- custom name
Organizer.Undresses_Desc = {}
Organizer.Restocks_Desc = {}
Organizer.Buys_Desc = {}
Organizer.Sells_Desc = {}
Organizer.Scavengers_Desc = {}

Organizer.Organizers_Cont = {} -- default container
Organizer.Organizers_CloseCont = {} --close container flag
Organizer.Undresses_Cont = {}
Organizer.Restocks_Cont = {}
Organizer.Scavengers_Cont = {}

Organizer.Organizer = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id=NNNN }
Organizer.Undress = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id="id value" }
Organizer.Restock = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id="id value" }
Organizer.Buy = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id="id value" }
Organizer.Sell = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id="id value" }
Organizer.Scavenger = {} -- each item: { name=L"", type=NNNN, hue=NNNN, id="id value" }

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

function Organizer.GetOrganizerName(i)
	local name = L" Organizer " .. i
	if (Organizer.Organizers_Desc[i] ~= L"") then
		name = Organizer.Organizers_Desc[i]
	end
	return name
end
function Organizer.Initialize()
	Organizer.Organizers = Interface.LoadNumber( "OrganizerOrganizers" , 1 )
	Organizer.Undresses = Interface.LoadNumber( "OrganizerUndresses" , 1 )
	Organizer.Restocks = Interface.LoadNumber( "OrganizerRestocks" , 1 )
	Organizer.Buys = Interface.LoadNumber( "OrganizerBuys" , 1 )
	Organizer.Sells = Interface.LoadNumber( "OrganizerSells" , 1 )
	Organizer.Scavengers = Interface.LoadNumber( "OrganizerScavengers" , 1 )
	
	Organizer.ActiveOrganizer = Interface.LoadNumber( "OrganizerActiveOrganizer" , 1 )
	Organizer.ActiveUndress = Interface.LoadNumber( "OrganizerActiveUndress" , 1 )
	Organizer.ActiveRestock = Interface.LoadNumber( "OrganizerActiveRestock" , 1 )
	Organizer.ActiveBuy = Interface.LoadNumber( "OrganizerActiveBuy" , 1 )
	Organizer.ActiveSell = Interface.LoadNumber( "OrganizerActiveSell" , 1 )
	Organizer.ActiveScavenger = Interface.LoadNumber( "OrganizerActiveScavenger" , 1 )

	for i=1, Organizer.Organizers do
		Organizer.Organizers_Items[i] =  Interface.LoadNumber( "OrganizerOrganizers_Items" .. i , 0 )
		Organizer.Organizers_Desc[i] = Interface.LoadWString( "OrganizerOrganizers_Desc" .. i , L"" )
		Organizer.Organizers_Cont[i] =  Interface.LoadNumber( "OrganizerOrganizers_Cont" .. i , 0 )
		Organizer.Organizers_CloseCont[i] =  Interface.LoadBoolean( "OrganizerOrganizers_CloseCont" .. i , false )
		if not Organizer.Organizer[i] then
			Organizer.Organizer[i] = {}
		end
		if (Organizer.Organizers_Items[i] > 0) then
			for j=1,  Organizer.Organizers_Items[i] do
				local item = {name="", type=0, hue=0, id=0}
				item.name = Interface.LoadString( "Organizer" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Organizer" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Organizer" .. i .. "it" .. j .. "Hue" , 0 )
				item.id = Interface.LoadNumber( "Organizer" .. i .. "it" .. j .. "Id" , 0 )
				
				if not Organizer.Organizer[i][j] then
					Organizer.Organizer[i][j] = {}
				end
				Organizer.Organizer[i][j] = item
			end
		end
	end

	for i=1, Organizer.Undresses do
		Organizer.Undresses_Items[i] =  Interface.LoadNumber( "OrganizerUndresses_Items" .. i , 0 )
		Organizer.Undresses_Desc[i] =  Interface.LoadWString( "OrganizerUndresses_Desc" .. i , L"" )
		Organizer.Undresses_Cont[i] =  Interface.LoadNumber( "OrganizerUndresses_Cont" .. i , 0 )
		if not Organizer.Undress[i] then
			Organizer.Undress[i] = {}
		end
		if (Organizer.Undresses_Items[i] > 0) then
			for j=1,  Organizer.Undresses_Items[i] do
				local item = {name="", type=0, hue=0, id=0}
				item.name = Interface.LoadString( "Undress" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Undress" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Undress" .. i .. "it" .. j .. "Hue" , 0 )
				item.id = Interface.LoadNumber( "Undress" .. i .. "it" .. j .. "Id" , 0 )
				if not Organizer.Undress[i][j] then
					Organizer.Undress[i][j] = {}
				end
				Organizer.Undress[i][j] = item
			end
		end
	end

	for i=1, Organizer.Restocks do
		Organizer.Restocks_Items[i] =  Interface.LoadNumber( "OrganizerRestocks_Items" .. i , 0 )
		Organizer.Restocks_Desc[i] =  Interface.LoadWString( "OrganizerRestocks_Desc" .. i , L"" )
		Organizer.Restocks_Cont[i] =  Interface.LoadNumber( "OrganizerRestocks_Cont" .. i , 0 )
		if not Organizer.Restock[i] then
			Organizer.Restock[i] = {}
		end
		if (Organizer.Restocks_Items[i] > 0) then
			for j=1 , Organizer.Restocks_Items[i] do
				local item = {name="", type=0, hue=0, qta=0}
				item.name = Interface.LoadString( "Restock" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Restock" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Restock" .. i .. "it" .. j .. "Hue" , 0 )
				item.qta = Interface.LoadNumber( "Restock" .. i .. "it" .. j .. "Qta" , 0 )
				
				if not Organizer.Restock[i][j] then
					Organizer.Restock[i][j] = {}
				end
				Organizer.Restock[i][j] = item
			end
		end
	end

	for i=1, Organizer.Buys do
		Organizer.Buys_Items[i] =  Interface.LoadNumber( "OrganizerBuys_Items" .. i , 0 )
		Organizer.Buys_Desc[i] =  Interface.LoadWString( "OrganizerBuys_Desc" .. i , L"" )
		if not Organizer.Buy[i] then
			Organizer.Buy[i] = {}
		end
		if (Organizer.Buys_Items[i] > 0) then
			for j=1 , Organizer.Buys_Items[i] do
				local item = {name="", type=0, hue=0, qta=0}
				item.name = Interface.LoadString( "Buy" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Buy" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Buy" .. i .. "it" .. j .. "Hue" , 0 )
				item.qta = Interface.LoadNumber( "Buy" .. i .. "it" .. j .. "Qta" , 0 )
				
				if not Organizer.Buy[i][j] then
					Organizer.Buy[i][j] = {}
				end
				Organizer.Buy[i][j] = item
			end
		end
	end

	for i=1, Organizer.Sells do
		Organizer.Sells_Items[i] =  Interface.LoadNumber( "OrganizerSells_Items" .. i , 0 )
		Organizer.Sells_Desc[i] =  Interface.LoadWString( "OrganizerSells_Desc" .. i , L"" )
		if not Organizer.Sell[i] then
			Organizer.Sell[i] = {}
		end
		if (Organizer.Sells_Items[i] > 0) then
			for j=1 , Organizer.Sells_Items[i] do
				local item = {name="", type=0, hue=0, qta=0}
				item.name = Interface.LoadString( "Sell" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Sell" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Sell" .. i .. "it" .. j .. "Hue" , 0 )
				item.qta = Interface.LoadNumber( "Sell" .. i .. "it" .. j .. "Qta" , 0 )
				
				if not Organizer.Sell[i][j] then
					Organizer.Sell[i][j] = {}
				end
				Organizer.Sell[i][j] = item
			end
		end
	end
	
	for i=1, Organizer.Scavengers do
		Organizer.Scavengers_Items[i] =  Interface.LoadNumber( "OrganizerScavengers_Items" .. i , 0 )
		Organizer.Scavengers_Desc[i] =  Interface.LoadWString( "OrganizerScavengers_Desc" .. i , L"" )
		Organizer.Scavengers_Cont[i] =  Interface.LoadNumber( "OrganizerScavengers_Cont" .. i , 0 )
		if not Organizer.Scavenger[i] then
			Organizer.Scavenger[i] = {}
		end
		if (Organizer.Scavengers_Items[i] > 0) then
			for j=1 , Organizer.Scavengers_Items[i] do
				local item = {name="", type=0, hue=0, qta=0}
				item.name = Interface.LoadString( "Scavenger" .. i .. "it" .. j .. "Name" , "Unnamed" )
				item.type = Interface.LoadNumber( "Scavenger" .. i .. "it" .. j .. "Type" , 0 )
				item.hue = Interface.LoadNumber( "Scavenger" .. i .. "it" .. j .. "Hue" , 0 )
				
				if not Organizer.Scavenger[i][j] then
					Organizer.Scavenger[i][j] = {}
				end
				Organizer.Scavenger[i][j] = item
			end
		end
	end
end