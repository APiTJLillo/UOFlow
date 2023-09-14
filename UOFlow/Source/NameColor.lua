----------------------------------------------------------------
-- Global Variables
----------------------------------------------------------------

NameColor = {}

----------------------------------------------------------------
-- Local Variables
----------------------------------------------------------------

NameColor.Notoriety = { NONE = 1, INNOCENT = 2, FRIEND = 3, CANATTACK =4, CRIMINAL=5, ENEMY=6, MURDERER=7, INVULNERABLE=8 }

NameColor.TextColors = {}
NameColor.TextColors[NameColor.Notoriety.NONE]         = { r=225, g=225, b=225 } --- GREY/SYS
NameColor.TextColors[NameColor.Notoriety.INNOCENT]     = { r=128, g=200, b=255 } --- BLUE
NameColor.TextColors[NameColor.Notoriety.FRIEND]       = { r=0 ,  g=180, b=0   } --- GREEN 
NameColor.TextColors[NameColor.Notoriety.CANATTACK]    = { r=225, g=225, b=225 } --- GREY/SYS
NameColor.TextColors[NameColor.Notoriety.CRIMINAL]     = { r=225, g=225, b=225 } --- GREY/SYS
NameColor.TextColors[NameColor.Notoriety.ENEMY]        = { r=242, g=159, b=77  } --- ORANGE
NameColor.TextColors[NameColor.Notoriety.MURDERER]     = { r=255, g=64,  b=64  } --- RED  
NameColor.TextColors[NameColor.Notoriety.INVULNERABLE] = { r=255, g=255, b=0   } --- YELLOW 

NameColor.AuraColors = {}
NameColor.AuraColors[NameColor.Notoriety.NONE]         = { r=225, g=225, b=225 } --- GREY/SYS
NameColor.AuraColors[NameColor.Notoriety.INNOCENT]     = { r=0, g=130, b=255 } --- BLUE
NameColor.AuraColors[NameColor.Notoriety.FRIEND]       = { r=0 ,  g=255, b=0   } --- GREEN 
NameColor.AuraColors[NameColor.Notoriety.CANATTACK]    = { r=70, g=70, b=70 } --- GREY/SYS
NameColor.AuraColors[NameColor.Notoriety.CRIMINAL]     = { r=70, g=70, b=70 } --- GREY/SYS
NameColor.AuraColors[NameColor.Notoriety.ENEMY]        = { r=242, g=159, b=77  } --- ORANGE
NameColor.AuraColors[NameColor.Notoriety.MURDERER]     = { r=255, g=0,  b=0  } --- RED  
NameColor.AuraColors[NameColor.Notoriety.INVULNERABLE] = { r=255, g=255, b=0   } --- YELLOW 

----------------------------------------------------------------
-- Functions
----------------------------------------------------------------

function NameColor.UpdateLabelNameColor(windowTextName, visualStateId)
	local textColor = NameColor.TextColors[visualStateId]
	LabelSetTextColor(windowTextName, textColor.r, textColor.g, textColor.b)
end

function NameColor.UpdateEditBoxNameColor(windowTextName, visualStateId)
	local textColor = NameColor.TextColors[visualStateId]
	TextEditBoxSetTextColor(windowTextName, textColor.r, textColor.g, textColor.b)
end