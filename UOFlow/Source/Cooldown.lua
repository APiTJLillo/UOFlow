----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

Cooldown = {}

 
----------------------------------------------------------------
-- Cooldown Functions
----------------------------------------------------------------

Cooldown.Frames = 1000

function Cooldown.Initialize()
	local sc = WindowGetScale(WindowGetParent(SystemData.ActiveWindow.name))
	WindowSetScale(SystemData.ActiveWindow.name, sc)
end