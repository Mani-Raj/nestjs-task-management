import { EntityRepository, Repository } from "typeorm";
import { Task } from "./task.entity";
import { CreateTaskDto } from "./dto/create-task.dto";
import { TaskStatus } from "./task-status.enum";
import { Injectable } from "@nestjs/common";

@EntityRepository(Task)
export class TasksRepository extends Repository<Task> {
    

    // async createTask(createTaskDto: CreateTaskDto): Promise<Task> {
    //     const { title, description } = createTaskDto;

    //     console.log(this)
    //     const task = this.create({
    //         title,
    //         description,
    //         status: TaskStatus.OPEN
    //     });

    //     await this.save(task);

    //     return task;
    // }

    check() {
        console.log('check repository')
    }
}