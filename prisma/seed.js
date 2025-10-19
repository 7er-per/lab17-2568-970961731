import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt"; 
import { v4 as uuidv4 } from "uuid";

const prisma = new PrismaClient();

async function main() {
  await prisma.task.deleteMany({});
  await prisma.user.deleteMany({});
  const hashedPassword = await bcrypt.hash("123456789", 10);

  const users = [
    {
      userId: uuidv4(),
      firstName: "Thanya",
      lastName: "Thanon",
      username: "thanya",
      password: hashedPassword,
      dateOfBirth: new Date("1999-05-20"),
      createAt: new Date("2024-12-31"),
      updateAt: new Date("2024-12-31"),
    },
    {
      userId: uuidv4(),
      firstName: "John",
      lastName: "Doe",
      username: "john",
      password: hashedPassword,
      dateOfBirth: new Date("2000-01-01"),
      createAt: new Date("2024-12-31"),
      updateAt: new Date("2024-12-31"),
    },
  ];

  await prisma.user.createMany({ data: users });

  const tasks = [
    {
      userId: "d10d8f3f-ae0e-4ba9-aa58-3e3f95447890",
      taskId: "d10d8f3f-ae0e-4ba9-aa58-3e3f9544732c",
      title: "Iphone 17 pro max",
      description: "Iphone 17 pro max with 1TB storage and 5G support",
      dueDate: new Date("2024-12-31"),
      doneAt: new Date("2024-12-31"),
      isDone: true,
      filename: "iphone17.jpg",
      createAt: new Date("2024-12-31"),
      updateAt: new Date("2024-12-31"),
    },
    {
      userId: "f7591220-9d56-40e3-bc85-9fcd3cb4fy12",
      taskId: "f7591220-9d56-40e3-bc85-9fcd3cb4fda3",
      title: "Iphone 13 pro max",
      description: "Iphone 13 pro max with 1TB storage and 5G support",
      dueDate: new Date("2024-12-31"),
      doneAt: new Date("2024-12-31"),
      isDone: true,
      filename: "iphone13.jpg",
      createAt: new Date("2024-12-31"),
      updateAt: new Date("2024-12-31"),
    },
  ];

  await prisma.task.createMany({ data: tasks });

  console.log("✅ Database seeded successfully!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
