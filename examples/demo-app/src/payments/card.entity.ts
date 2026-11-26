import { Entity, Column, PrimaryGeneratedColumn } from "typeorm";

@Entity("saved_cards")
export class SavedCard {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  cardNumber: string;

  @Column()
  cvv: string;

  @Column()
  expiry: string;
}
