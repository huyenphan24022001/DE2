USE [DE2]
GO
/****** Object:  Table [dbo].[TinTuc]    Script Date: 7/29/2024 11:52:39 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TinTuc](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[TieuDe] [nvarchar](255) NULL,
	[MoTaNgan] [nvarchar](255) NULL,
	[NoiDung] [text] NULL,
	[HinhAnh] [nvarchar](255) NULL,
	[NgayDang] [datetime] NULL,
	[IsDelete] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Token]    Script Date: 7/29/2024 11:52:39 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Token](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Users_ID] [int] NULL,
	[access_token] [nvarchar](255) NULL,
	[refresh_token] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Users]    Script Date: 7/29/2024 11:52:39 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserName] [nvarchar](255) NOT NULL,
	[Pass] [nvarchar](255) NULL,
	[Role] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[TinTuc] ON 

INSERT [dbo].[TinTuc] ([ID], [TieuDe], [MoTaNgan], [NoiDung], [HinhAnh], [NgayDang], [IsDelete]) VALUES (1, N'test', N'testjvhjfejhhdfdjdjdjdjdjd', N'Hình nhu trong lòng anh dã không còn hình bóng ai ngoài em dâu

H?ng dêm, anh n?m thao th?c suy tu ch?ng nh? ai ngoài em dâu

V?y nên không c?n nói n?a, yêu mà dòi nói trong vài ba câu

C? c? quá dâm ra l?i hâm.. Uh, dau h?t c? d?u!

Ð?i ch? em tru?c nhà t? sáng d?n trua chi?u t?i, m?c màn dây luôn

Ngu?c n?ng hay là ngu?c gió mi?n anh th?y em tuoi vui không bu?n

Ch? c?n có th?y th? thôi mây xanh chan hòa

Th?y th? thôi vui hon có quà

Và bu?c k? ti?p anh l?i g?n hon chút dó nha

R?i ngày ?y cu?i cùng dã tìm d?n ta nào dâu hay

Anh s? không d? v?t m?t di co duyên ông tr?i trao tay

Còn d?n do ban khoan gì n?a ti?p c?n em ngay

', N'beauty-pie-review-9.jpg', CAST(N'2024-06-11T11:15:48.863' AS DateTime), 1)
INSERT [dbo].[TinTuc] ([ID], [TieuDe], [MoTaNgan], [NoiDung], [HinhAnh], [NgayDang], [IsDelete]) VALUES (2, N'test edit 2', N'fffdff', N'ddddd', N'kinh-nghiem-du-lich-mien-tay-song-nuoc-tu-tuc-chi-tiet-nhat1.jpg', CAST(N'2024-06-11T11:10:53.980' AS DateTime), 0)
INSERT [dbo].[TinTuc] ([ID], [TieuDe], [MoTaNgan], [NoiDung], [HinhAnh], [NgayDang], [IsDelete]) VALUES (3, N'Red Carpet Ready', N'I kick off with some zingy shower gel.  Sweet Orange, Lemon, Grapefruit, Black Pepper and aloe vera turn the shower into an aromatic steam room that makes me feel like I’m in a spa.', N'Previously when getting ready for a big event with lots of photographer’s I’d have gone to a facialist and spent lots of money being plucked, plumped and buffed, and while that can be lovely, I now know it’s not necessary.

I was introduced to Beauty Pie by a friend of mine who used to work for one of the bigger luxury beauty brands. She explained how much of a mark-up we’re spending on some of the bigger brand names, and that you can get the same level of quality products online, without all the fluff and extra costs.

It’s essentially a membership that gives you access to luxury beauty & wellness products at lab-direct pricing. They remove the middlemen – retailer markups, expensive shop fits and pricey packaging.', N'beauty-pie-review-9.jpg', CAST(N'2024-06-11T10:48:00.087' AS DateTime), 0)
SET IDENTITY_INSERT [dbo].[TinTuc] OFF
GO
SET IDENTITY_INSERT [dbo].[Token] ON 

INSERT [dbo].[Token] ([ID], [Users_ID], [access_token], [refresh_token]) VALUES (1, 1, N'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJRCI6IjEiLCJVc2VyTmFtZSI6ImFkbWluIiwiUm9sZSI6IjEiLCJleHAiOjE3MjIyMzIxNjd9.AynszS9OxiaUNgxUlJjs8j6vC27KY3Ll-i2Ks5uB1pM', N'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJRCI6IjEiLCJVc2VyTmFtZSI6ImFkbWluIiwiUm9sZSI6IjEiLCJleHAiOjE3MjI4MzMzNjd9.OKXbMX_8iJ917lPBkGrmDwxz9HtpDhphdSBzk8yX4Gc')
SET IDENTITY_INSERT [dbo].[Token] OFF
GO
SET IDENTITY_INSERT [dbo].[Users] ON 

INSERT [dbo].[Users] ([ID], [UserName], [Pass], [Role]) VALUES (1, N'admin', N'f52EmOY2EqOlO+TvezMgDgWOo+sI249P1hzRKVcu1gE=', 1)
INSERT [dbo].[Users] ([ID], [UserName], [Pass], [Role]) VALUES (2, N'test', N'f52EmOY2EqOlO+TvezMgDgWOo+sI249P1hzRKVcu1gE=', 1)
SET IDENTITY_INSERT [dbo].[Users] OFF
GO
ALTER TABLE [dbo].[Token]  WITH CHECK ADD FOREIGN KEY([Users_ID])
REFERENCES [dbo].[Users] ([ID])
GO
