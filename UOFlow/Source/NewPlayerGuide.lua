----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

NewPlayerGuide = { }

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

-- All the text ids we want to display in the center window
local textlayout =
{
	1077642,	-- Introduction and Movement
	1077643,	-- Items and Inventory
	1077644,	-- NPC Interaction and Equipment
	1077645,	-- ""
	1077646,	-- Navigation
	1077647,	-- First Combat
	1077648,	-- First Loot
	1077649,	-- ""
	1077650,	-- Zombies
	1077651,	-- The Healer
	1077652,  	-- The Player's Corpse
	1077653,	-- An Unexpected Challenge
	1077654		-- The Purpose of New Haven
}

local this = "NewPlayerGuide"
local step = 0

-- Set the next section of text to display
-- If we're done, simply destroy the window
function NewPlayerGuide.SetText()
	step = step + 1
	if (step > (table.getn(textlayout))) then
		Interface.QueueWindowForDestroy(this)
	else
		LabelSetText("NewPlayerGuideEntry1Text", GetStringFromTid(textlayout[step]))
	end
end

function NewPlayerGuide.Initialize()
	step = 0
	WindowUtils.SetActiveDialogTitle(L"Gwen")
	NewPlayerGuide.SetText()
end

function NewPlayerGuide.Shutdown()
	step = 0
end